//! The writes, `add`, `edit` and `remove`, as a vault client (ADR 0025, data model §1.1). Each is confirmed by the
//! user every time (no grant counts and "always" is never offered) and refused to an AI-class or an unknown caller.
//! The new values are asked for here, in the trusted pinentry, so they never travel over the socket; or, for the rbw
//! shim (whose `$EDITOR` runs in the CLI, as rbw's does), they come with the request, and the write is confirmed all
//! the same. An edit or a
//! remove of an item that asks for a reprompt needs the master password first. `generate` is an `add` whose password the
//! agent makes itself. A new login's folder that does not exist yet is created with it, as rbw does.
//!
//! The body is the core's (`vault::client`), planned on the server's copy fetched right before it is sent and based
//! on the revision the user was asked about: a copy that changed since is refused (`OutOfDate`) and nothing is
//! written (§6.5). Everything the edit does not change passes through as the server holds it (§6.3). A remove moves
//! the item to the trash, never purges it. A sync follows every write.

use dybw_core::api::{ApiError, Client};
use dybw_core::ports::Http;
use dybw_core::vault::client::{self, ClientEdit, NewEntry, NewKind, NewLogin, NewUri};
use dybw_core::vault::write::WriteError;
use dybw_native::ports::clock::SystemClock;
use dybw_native::ports::random::OsRandom;
use dybw_proto::{Charset, Part, Sealed};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::*;
use crate::pwgen;

/// A change of the vault: what the client sent, its values (`given`) redacted in `Debug`.
#[derive(Debug)]
pub enum Write {
    /// A new personal login; the agent asks for each of `ask`, and with `generate` makes the password itself.
    Add {
        name: String,
        user: Option<String>,
        uris: Vec<String>,
        folder: Option<String>,
        ask: Vec<Part>,
        generate: Option<(Charset, u32)>,
        given: Vec<(Part, Sealed)>,
    },
    /// New values for `ask` (asked for) and `given` (sent) of one item: the password, the notes; or rbw's edit `text`,
    /// split by the item's type once it is found.
    Edit { find: Lookup, ask: Vec<Part>, given: Vec<(Part, Sealed)>, text: Option<Sealed> },
    /// Move one item to the trash.
    Remove { find: Lookup },
}

impl Write {
    fn op(&self) -> &'static str {
        match self {
            Write::Add { generate: Some(_), .. } => "generate",
            Write::Add { .. } => "add",
            Write::Edit { .. } => "edit",
            Write::Remove { .. } => "remove",
        }
    }

    fn asked(&self) -> &[Part] {
        match self {
            Write::Add { ask, .. } | Write::Edit { ask, .. } => ask,
            Write::Remove { .. } => &[],
        }
    }

    fn given(&self) -> &[(Part, Sealed)] {
        match self {
            Write::Add { given, .. } | Write::Edit { given, .. } => given,
            Write::Remove { .. } => &[],
        }
    }
}

/// What is looked up before the user is asked.
struct Planned {
    /// The item an edit or a remove is about.
    found: Option<Found>,
    /// Its id, and the revision of the copy the user is asked about.
    id: String,
    base: String,
    /// The item's name, or the new login's.
    name: String,
    /// The folder a new login goes to: its id, or the name of one to create (it did not exist at the plan).
    folder: Option<Result<String, String>>,
    /// The namespaces that mark the item a remove is about.
    markers: Vec<String>,
    /// The values the client sent (an edit `text` split by the item's type).
    given: Vec<(Part, Sealed)>,
}

/// A write refused before anything is sent, by its fixed code.
fn refused_as(code: &str) -> AgentError {
    AgentError::WriteRefused(code.to_owned())
}

/// The core's refusal for the client: `OutOfDate` as such, the others by their code.
fn refused(e: WriteError) -> AgentError {
    if matches!(e, WriteError::OutOfDate) {
        return AgentError::OutOfDate;
    }
    tracing::warn!("write refused: {e}");
    refused_as(e.code().unwrap_or("invalid"))
}

fn plan(v: &UnlockedVault, write: &Write) -> Result<Planned, AgentError> {
    let planned = |found: Found, markers| Planned {
        id: found.id.clone(),
        base: read::revision(v, &found.id),
        name: found.name.clone(),
        found: Some(found),
        folder: None,
        markers,
        given: write.given().to_vec(),
    };
    match write {
        Write::Add { generate: Some((_, n)), .. } if !(1..=pwgen::MAX_LENGTH).contains(n) => Err(refused_as("length")),
        Write::Add { name, folder, .. } => Ok(Planned {
            found: None,
            id: String::new(),
            base: String::new(),
            name: name.clone(),
            folder: folder.as_deref().map(|f| read::folder_id(v, f).map_err(|_| f.to_owned())),
            markers: Vec::new(),
            given: write.given().to_vec(),
        }),
        // The core edits the name, notes, user, password, URIs and folder: no TOTP key.
        Write::Edit { ask, .. } if ask.contains(&Part::Totp) => Err(refused_as("totp-edit")),
        Write::Edit { ask, given, text: None, .. } if ask.is_empty() && given.is_empty() => {
            Err(refused_as("nothing-to-change"))
        }
        Write::Edit { find, text: Some(text), .. } => {
            let found = read::find(v, find)?;
            let kind = read::cipher(v, &found.id).and_then(|c| c.get("type")).and_then(Value::as_u64);
            if !matches!(kind, Some(1 | 2)) {
                return Err(refused_as("rbw-type"));
            }
            let (password, notes) =
                crate::rbw_view::edit_values(text.expose(), kind == Some(1)).ok_or_else(|| refused_as("empty"))?;
            let mut planned = planned(found, Vec::new());
            planned.given.extend(password.map(|p| (Part::Password, p)));
            planned.given.push((Part::Notes, notes));
            Ok(planned)
        }
        Write::Edit { find, .. } => Ok(planned(read::find(v, find)?, Vec::new())),
        Write::Remove { find } => {
            let found = read::find(v, find)?;
            let markers = read::markers(v, &found.id)?;
            Ok(planned(found, markers))
        }
    }
}

fn label(part: Part) -> (&'static str, &'static str) {
    match part {
        Part::Password => ("New password:", "the password"),
        Part::Notes => ("Notes:", "the notes"),
        Part::Totp => ("TOTP key:", "the TOTP key (an otpauth:// URI or a base32 secret)"),
    }
}

/// The confirmation: the profile, who asks and by which command, what is done to which item; for a remove of a marked
/// item, the namespaces that lose it.
fn question(ctx: &Ctx, caller: &Caller, write: &Write, planned: &Planned) -> String {
    let name = tidy(&planned.name);
    let item = planned.found.as_ref().map_or_else(|| format!("\"{name}\""), item_text);
    let what = match write {
        Write::Add { user, folder, uris, generate, .. } => {
            let user = user.as_deref().map(|u| format!(" for the user \"{}\"", tidy(u))).unwrap_or_default();
            let new = if matches!(planned.folder, Some(Err(_))) { "new " } else { "" };
            let folder = folder.as_deref().map(|f| format!(" in the {new}folder \"{}\"", tidy(f))).unwrap_or_default();
            let made = generate.map(|(_, n)| format!(" and a generated password ({n} {})", unit(generate)));
            format!("add the login \"{name}\"{user}{folder}{}{}", uri_list(uris), made.unwrap_or_default())
        }
        Write::Edit { ask, .. } => {
            let parts: Vec<_> = planned.given.iter().map(|(p, _)| p).chain(ask).map(|p| label(*p).1).collect();
            format!("change {} of the item {item}", parts.join(" and "))
        }
        Write::Remove { .. } if !planned.markers.is_empty() => format!(
            "move the item {item} to the trash; it is marked for {}, whose tools lose it",
            policy::shown(&planned.markers.join(", "), 200)
        ),
        Write::Remove { .. } => format!("move the item {item} to the trash"),
    };
    format!(
        "dybw profile {}: allow {} (dybw {}) to {what}? (asked for every change)",
        ctx.profile.name,
        policy::who(caller),
        write.op()
    )
}

/// What a generated password's length counts.
fn unit(generate: &Option<(Charset, u32)>) -> &'static str {
    if matches!(generate, Some((Charset::Diceware, _))) { "words" } else { "characters" }
}

/// How many URIs a question names; the others are counted.
const URIS_SHOWN: usize = 3;

/// The URIs a new login gets, for its question: each on one line and cut, the first few and how many more.
fn uri_list(uris: &[String]) -> String {
    if uris.is_empty() {
        return String::new();
    }
    let shown: Vec<_> = uris.iter().take(URIS_SHOWN).map(|u| format!("\"{}\"", tidy(u))).collect();
    let more = uris.len().saturating_sub(URIS_SHOWN);
    let more = if more > 0 { format!(" and {more} more") } else { String::new() };
    format!(" with the URIs {}{more}", shown.join(", "))
}

/// The new values: those the client sent, a generated password, then each asked part from the pinentry. A TOTP key that gives no code is
/// refused here, before anything is sent.
async fn values<H: Host>(
    host: &H,
    ctx: &Ctx,
    planned: &Planned,
    write: &Write,
) -> Result<Vec<(Part, Zeroizing<String>)>, AgentError> {
    let (ask, name) = (write.asked(), &planned.name);
    let mut out = Vec::with_capacity(ask.len() + 3);
    out.extend(planned.given.iter().map(|(p, v)| (*p, Zeroizing::new(v.expose().to_owned()))));
    if let Write::Add { generate: Some((charset, length)), .. } = write {
        // The length was checked in the plan, and the OS random source does not fail.
        out.push((Part::Password, pwgen::generate(&OsRandom, *charset, *length).ok().ok_or(AgentError::Internal)?));
    }
    for part in ask {
        let (prompt, what) = label(*part);
        let description = format!(
            "dybw profile {}: the new value of {what} of the item \"{}\" (NOT your master password)",
            ctx.profile.name,
            tidy(name)
        );
        let value = session::ask(host, prompt, &description, None).await?;
        if *part == Part::Totp {
            dybw_core::totp::TotpKey::parse(&value).map_err(|e| AgentError::Totp(e.to_string()))?;
        }
        out.push((*part, value));
    }
    Ok(out)
}

/// What is sent: a create, an update (`None`: it changes nothing, nothing is sent) or a trash.
enum Body {
    Create(Map<String, Value>),
    Update(Option<Map<String, Value>>),
    Trash,
}

/// The core's body for `write`, on `v`'s copy (fetched right before), with the user's new values.
fn body(
    v: &UnlockedVault,
    write: &Write,
    planned: &Planned,
    folder_id: Option<String>,
    values: &[(Part, Zeroizing<String>)],
    now_ms: i64,
) -> Result<Body, AgentError> {
    let value = |p: Part| values.iter().rev().find(|(q, _)| *q == p).map(|(_, v)| v.clone());
    let text = |s: &str| Zeroizing::new(s.to_owned());
    let (user, orgs) = (v.keys.user(), v.keys.orgs());
    let cipher = || read::cipher(v, &planned.id).ok_or_else(|| refused(WriteError::Gone));
    match write {
        Write::Add { name, user: login, uris, .. } => {
            let entry = NewEntry {
                name: text(name),
                notes: value(Part::Notes).unwrap_or_default(),
                folder_id,
                kind: NewKind::Login(NewLogin {
                    username: text(login.as_deref().unwrap_or_default()),
                    password: value(Part::Password).unwrap_or_default(),
                    totp: value(Part::Totp).unwrap_or_default(),
                    uris: uris.iter().map(|u| NewUri { uri: text(u), match_type: None }).collect(),
                }),
            };
            client::create(&entry, user, v.security_version, &OsRandom).map(Body::Create).map_err(refused)
        }
        Write::Edit { .. } => {
            let edit = ClientEdit {
                base_revision: planned.base.clone(),
                password: value(Part::Password),
                notes: value(Part::Notes),
                ..ClientEdit::default()
            };
            client::edit(cipher()?, &edit, user, orgs, &OsRandom, now_ms).map(Body::Update).map_err(refused)
        }
        Write::Remove { .. } => {
            client::check_trash(cipher()?, &planned.base, user, orgs).map(|()| Body::Trash).map_err(refused)
        }
    }
}

/// Make the folder `name` (encrypted under the user key) on the server: its id.
async fn new_folder<H: Http>(
    shared: &Shared,
    api: &mut Client<H, SystemClock>,
    name: &str,
) -> Result<String, AgentError> {
    let encrypted =
        with_vault(shared, |v| v.keys.user().encrypt_str(name, &OsRandom).ok().ok_or(AgentError::Internal))?;
    let made = api.create_folder(&encrypted).await.map_err(|e| session::map_api(&e))?;
    made.get("id").and_then(Value::as_str).map(str::to_owned).ok_or(AgentError::Server)
}

/// Fetch the server's copy, plan the body on it, send it, then sync. The item's id (a new login's from the server).
async fn send<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    write: &Write,
    planned: &Planned,
    values: &[(Part, Zeroizing<String>)],
    still: &Recheck,
) -> Result<Option<String>, AgentError> {
    let target = shared.state.borrow().slot.as_ref().map(|s| (s.origin.clone(), s.urls.clone()));
    let Some((origin, urls)) = target else { return Err(AgentError::Locked) };
    // One login, unlock, sync or write at a time.
    let _op = shared.op.lock().await;
    // The wait for another operation may have been long: the peer must still be the one that asked.
    if !still.holds() {
        tracing::warn!(profile = %ctx.profile.name, "the caller changed while the write waited its turn");
        return Err(AgentError::Denied);
    }
    let (mut api, fresh) = session::connect(host, ctx, &origin, &urls).await?;
    install(shared, ctx, fresh).await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let now_ms = i64::try_from(now.as_millis()).unwrap_or(i64::MAX);
    let sent = |e: ApiError| if e.is_out_of_date() { AgentError::OutOfDate } else { session::map_api(&e) };
    // A folder that did not exist at the plan may have been made meanwhile (it is on the fresh copy); else make it.
    let found = |name: &str| with_vault(shared, |v| read::folder_id(v, name)).ok();
    let folder_id = match &planned.folder {
        None => None,
        Some(Ok(id)) => Some(id.clone()),
        Some(Err(name)) => {
            Some(if let Some(id) = found(name) { id } else { new_folder(shared, &mut api, name).await? })
        }
    };
    let body = with_vault(shared, |v| body(v, write, planned, folder_id, values, now_ms))?;
    let id = match body {
        Body::Create(b) => {
            api.create_cipher(b).await.map_err(sent)?.get("id").and_then(Value::as_str).map(str::to_owned)
        }
        Body::Update(Some(b)) => {
            api.update_cipher(&planned.id, b).await.map(|_| Some(planned.id.clone())).map_err(sent)?
        }
        Body::Update(None) => Some(planned.id.clone()),
        Body::Trash => api.trash_cipher(&planned.id).await.map(|()| Some(planned.id.clone())).map_err(sent)?,
    };
    // The write is done: a sync that fails after it only leaves the copy behind until the next one (and is logged).
    if let Ok(after) = api.sync().await.map_err(|e| session::map_api(&e)) {
        install(shared, ctx, after).await;
    }
    Ok(id)
}

/// `add`, `edit` and `remove`: plan (a missing or ambiguous item ends here, with no prompt), the policy (never a
/// grant), the user's yes, the reprompt, the new values, the peer and item checks, then the write. Every outcome after
/// the plan is audited.
pub(super) async fn write<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    still: &Recheck,
    write: Write,
) -> Reply {
    let op = (write.op(), None);
    // Before the plan: a caller the policy refuses makes the agent open nothing.
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    if policy::decide(caller, &store.load(), &[], Access::Write) == Decision::Deny {
        audit(ctx, caller, op, None, Verdict::Denied);
        return error(AgentError::Denied);
    }
    let planned = match with_vault(shared, |v| plan(v, &write)) {
        Ok(planned) => planned,
        Err(e) => return error(e),
    };
    let item = planned.found.as_ref().map(|f| f.id.clone());
    let end = |verdict, e| {
        audit(ctx, caller, op, item.as_deref(), verdict);
        error(e)
    };
    let values = {
        let _screen = shared.asking.lock().await;
        // A removal that takes an item from other tools says so in the pinentry only.
        let touch = planned.markers.is_empty().then(|| {
            let name = planned.found.as_ref().map_or(&planned.name, |f| &f.name);
            super::touch_reason(&ctx.profile.name, caller, &format!("{} {}", write.op(), super::touch_name(name)))
        });
        if let Err(e) = session::confirm(host, &question(ctx, caller, &write, &planned), touch, false).await {
            return end(Verdict::Declined, e);
        }
        if let Some(found) = planned.found.as_ref().filter(|f| f.reprompt)
            && let Err(e) = reprompt(shared, host, ctx, caller, found, op).await
        {
            return error(e);
        }
        match values(host, ctx, &planned, &write).await {
            Ok(values) => values,
            Err(e @ (AgentError::Totp(_) | AgentError::Internal)) => return end(Verdict::Failed, e),
            Err(e) => return end(Verdict::Declined, e),
        }
    };
    if !still.holds() {
        tracing::warn!(profile = %ctx.profile.name, "the caller changed while the user was asked");
        return end(Verdict::Denied, AgentError::Denied);
    }
    if let Some(found) = &planned.found
        && let Err(e) = with_vault(shared, |v| same_item(ctx, v, found))
    {
        return end(Verdict::Denied, e);
    }
    match send(shared, host, ctx, &write, &planned, &values, still).await {
        Ok(id) => {
            audit(ctx, caller, op, id.as_deref(), Verdict::Confirmed);
            Reply::Done
        }
        Err(AgentError::Denied) => end(Verdict::Denied, AgentError::Denied),
        Err(e) => end(Verdict::Failed, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_question_names_the_first_uris_and_counts_the_others() {
        let uris = |n: usize| (1..=n).map(|i| format!("https://{i}.invalid\nx")).collect::<Vec<_>>();
        assert_eq!(uri_list(&[]), "");
        assert_eq!(uri_list(&uris(1)), " with the URIs \"https://1.invalid\u{fffd}x\"");
        assert_eq!(
            uri_list(&uris(5)),
            " with the URIs \"https://1.invalid\u{fffd}x\", \"https://2.invalid\u{fffd}x\", \"https://3.invalid\u{fffd}x\" and 2 more"
        );
    }
}
