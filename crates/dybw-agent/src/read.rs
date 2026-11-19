//! The read operations (ADR 0025). `list` and `search` show what `item::summary` decrypts (name, user, folder, type)
//! and nothing more. `get` and `history` find one item by its summary, and only after the worker's value gate
//! (a confirmation the user answered) open it, put what was asked in the reply, and drop it. Nothing is kept
//! between requests: every opened item is wiped before these functions return, and the reply carries only what was
//! asked. No function here prompts or waits.

use dybw_core::profile::UnlockedVault;
use dybw_core::totp::TotpKey;
use dybw_core::vault::folder::{FolderNames, folder_names};
use dybw_core::vault::item::{self, Data, Identity, Item, Summary, Text};
use dybw_core::vault::scan::Uninspectable;
use dybw_proto::{AgentError, Candidate, Entry, Field, HistoryEntry, ItemSummary, Reply, Secret, Select};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;
use zeroize::Zeroizing;

/// How a client names the item it wants (rbw's `get` arguments).
#[derive(Debug, Clone)]
pub struct Lookup {
    pub needle: String,
    pub user: Option<String>,
    pub folder: Option<String>,
    pub ignorecase: bool,
}

/// The one item a lookup found: what the confirmation shows, never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub id: String,
    pub name: String,
    pub user: Option<String>,
    /// The name of its folder, when it is in one that reads.
    pub folder: Option<String>,
    /// An organization item: the organization's name, or its id when `/sync` gives no name.
    pub org: Option<String>,
    /// The cipher asks for the master password again (`reprompt`, a plain field) before any value or change.
    pub reprompt: bool,
    /// A login whose organization hides its password (`viewPassword: false`): its password, TOTP key and history are
    /// never given, as Bitwarden's clients hide them.
    pub hidden: bool,
}

// Opened items so far on this thread, for tests of the value gate (a worker is one thread).
#[cfg(test)]
thread_local! {
    pub(crate) static OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The only place an item is opened.
fn open(cipher: &Value, vault: &UnlockedVault) -> Result<Item, Uninspectable> {
    #[cfg(test)]
    OPENS.with(|n| n.set(n.get() + 1));
    item::open(cipher, vault.keys.user(), vault.keys.orgs())
}

/// The vault's ciphers that are not in the trash.
fn ciphers(sync: &Value) -> impl Iterator<Item = &Value> {
    let all = sync.get("ciphers").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    all.iter().filter(|c| c.get("deletedDate").is_none_or(Value::is_null))
}

/// Every readable cipher with its summary. One that cannot be read (a held organization item, a bad key) is
/// left out: it cannot be shown or matched.
fn summaries(vault: &UnlockedVault) -> Vec<(&Value, Summary)> {
    let mut skipped = 0;
    let rows = ciphers(&vault.sync)
        .filter_map(|c| match item::summary(c, vault.keys.user(), vault.keys.orgs()) {
            Ok(s) => Some((c, s)),
            Err(_) => {
                skipped += 1;
                None
            }
        })
        .collect();
    if skipped > 0 {
        tracing::info!(skipped, "items that cannot be read are left out");
    }
    rows
}

/// The name of a summary's folder; `None` for no folder or one that does not read.
fn folder_of<'a>(names: &'a FolderNames, s: &Summary) -> Option<&'a str> {
    names.get(s.folder_id.as_deref()?)?.ok()
}

fn kind_name(kind: u64) -> &'static str {
    match kind {
        1 => "Login",
        2 => "Note",
        3 => "Card",
        4 => "Identity",
        5 => "SshKey",
        _ => "Unknown",
    }
}

/// `list` (no term) and `search` (a case-insensitive part of the name or the user): only the fields asked for are
/// filled. Folder names are decrypted only when shown or filtered on.
pub fn list(vault: &UnlockedVault, fields: &[Field], folder: Option<&str>, term: Option<&str>) -> Reply {
    let want = |f| fields.contains(&f);
    let names = (want(Field::Folder) || folder.is_some()).then(|| folder_names(&vault.sync, vault.keys.user()));
    let folder_name = |s: &Summary| names.as_ref().and_then(|n| folder_of(n, s));
    let term = term.map(str::to_lowercase);
    let has = |text: &str| term.as_deref().is_none_or(|t| text.to_lowercase().contains(t));
    let items = summaries(vault)
        .into_iter()
        .map(|(_, s)| s)
        .filter(|s| folder.is_none_or(|f| folder_name(s) == Some(f)))
        .filter(|s| term.is_none() || has(&s.name) || s.user.as_deref().is_some_and(|u| has(u)))
        .map(|s| ItemSummary {
            name: want(Field::Name).then(|| s.name.to_string()),
            user: s.user.as_deref().filter(|_| want(Field::User)).cloned(),
            folder: folder_name(&s).filter(|_| want(Field::Folder)).map(str::to_owned),
            kind: want(Field::Type).then(|| kind_name(s.kind).to_owned()),
            id: s.id,
        })
        .collect();
    Reply::Items { items }
}

/// rbw's lookup (rbw 1.15 `src/bin/rbw/commands.rs`: `parse_needle`, `find_entry`, `find_entry_raw`,
/// `DecryptedSearchCipher::matches`, `matches_url`), on what `item::summary_with_uris` decrypts: never a value.
/// A needle equal to an item's id (or the same UUID) is that item. Otherwise a URL with a special scheme (http, https,
/// ws, wss, ftp, file) is matched against each login's URIs by their match types, and anything else against the
/// names. rbw's passes: exact first, then a part; within each, an item with no folder and no user when neither was
/// given, then one of those two strict, then neither. Several matches are `Ambiguous`, naming id, name and user only.
pub fn find(vault: &UnlockedVault, q: &Lookup) -> Result<Found, AgentError> {
    let uuid = uuid::Uuid::parse_str(&q.needle).ok();
    let url = url::Url::parse(&q.needle).ok().filter(|u| uuid.is_none() && u.is_special());
    let rows = rows(vault, url.as_ref());
    let folders = folder_names(&vault.sync, vault.keys.user());
    let found = |r: &Row| Found {
        id: r.summary.id.clone(),
        name: r.summary.name.to_string(),
        user: r.summary.user.as_deref().cloned(),
        folder: folder_of(&folders, &r.summary).map(str::to_owned),
        org: r.cipher.get("organizationId").and_then(Value::as_str).map(|id| org_name(vault, id)),
        reprompt: r.cipher.get("reprompt").and_then(Value::as_u64).is_some_and(|n| n != 0),
        hidden: r.summary.kind == 1 && r.cipher.get("viewPassword") == Some(&Value::Bool(false)),
    };
    let by_id =
        |r: &&Row| r.summary.id == q.needle || uuid.is_some_and(|u| uuid::Uuid::parse_str(&r.summary.id) == Ok(u));
    if let Some(row) = rows.iter().find(by_id) {
        return Ok(found(row));
    }
    let matches = |r: &Row, strict_user: bool, strict_folder: bool, exact: bool| {
        let same = |field: &str, term: &str| match (q.ignorecase, exact) {
            (true, true) => field.to_lowercase() == term.to_lowercase(),
            (true, false) => field.to_lowercase().contains(&term.to_lowercase()),
            (false, true) => field == term,
            (false, false) => field.contains(term),
        };
        let given = |have: Option<&str>, want: Option<&str>, strict: bool| match (have, want) {
            (Some(have), Some(want)) => same(have, want),
            (Some(_), None) => !strict,
            (None, Some(_)) => false,
            (None, None) => true,
        };
        given(folder_of(&folders, &r.summary), q.folder.as_deref(), strict_folder)
            && given(r.summary.user.as_deref().map(|u| u.as_str()), q.user.as_deref(), strict_user)
            && if url.is_some() { r.uri_hit } else { same(&r.summary.name, &q.needle) }
    };
    let pick = |strict_user, strict_folder, exact| -> Vec<&Row> {
        rows.iter().filter(|r| matches(r, strict_user, strict_folder, exact)).collect()
    };
    let mut hits = Vec::new();
    for exact in [true, false] {
        hits = pick(true, true, exact);
        if let [one] = hits.as_slice() {
            return Ok(found(one));
        }
        match (pick(false, true, exact).as_slice(), pick(true, false, exact).as_slice()) {
            ([one], other) | (other, [one]) if other.len() != 1 => return Ok(found(one)),
            _ => {}
        }
        hits = pick(false, false, exact);
        if let [one] = hits.as_slice() {
            return Ok(found(one));
        }
    }
    if hits.is_empty() {
        return Err(AgentError::NotFound);
    }
    let candidates = hits
        .iter()
        .map(|r| Candidate {
            id: r.summary.id.clone(),
            name: r.summary.name.to_string(),
            user: r.summary.user.as_deref().cloned(),
        })
        .collect();
    Err(AgentError::Ambiguous { candidates })
}

/// The name `/sync` gives the organization `id`, else the id.
fn org_name(vault: &UnlockedVault, id: &str) -> String {
    let orgs = vault.sync.pointer("/profile/organizations").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    let org = orgs.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(id));
    org.and_then(|o| o.get("name")).and_then(Value::as_str).unwrap_or(id).to_owned()
}

/// A readable cipher with what a lookup decrypts of it, and whether one of its URIs matches the URL needle.
struct Row<'a> {
    cipher: &'a Value,
    summary: Summary,
    uri_hit: bool,
}

/// Every readable cipher with its summary; one that cannot be read is left out. The URIs are decrypted only for a
/// URL needle (`item::summary_with_uris`), and matched once per item here: the passes do not change that match.
fn rows<'a>(vault: &'a UnlockedVault, url: Option<&url::Url>) -> Vec<Row<'a>> {
    let Some(url) = url else {
        return summaries(vault).into_iter().map(|(cipher, summary)| Row { cipher, summary, uri_hit: false }).collect();
    };
    let read = |c| item::summary_with_uris(c, vault.keys.user(), vault.keys.orgs()).ok();
    let hit =
        |uris: &[item::Uri]| uris.iter().any(|u| text(&u.uri).is_some_and(|uri| matches_url(uri, u.match_type, url)));
    ciphers(&vault.sync)
        .filter_map(|cipher| read(cipher).map(|l| Row { cipher, uri_hit: hit(&l.uris), summary: l.summary }))
        .collect()
}

/// The most a stored regular expression may compile to: a bigger one matches nothing.
const REGEX_NFA_LIMIT: usize = 1 << 20;

/// Whether a stored URI with its Bitwarden match type (0 domain, the default; 1 host; 2 starts with; 3 exact;
/// 4 regular expression; 5 never) matches `given`, as rbw 1.15's `matches_url` (`src/bin/rbw/commands.rs`) does. A
/// match type rbw does not know matches nothing.
fn matches_url(uri: &str, match_type: Option<u64>, given: &url::Url) -> bool {
    let host_port = |u: &url::Url| u.host_str().map(|h| u.port().map_or_else(|| h.to_owned(), |p| format!("{h}:{p}")));
    let stored = url::Url::parse(uri).ok().filter(|s| s.scheme() == given.scheme()).and_then(|s| host_port(&s));
    match match_type.unwrap_or(0) {
        0 | 1 => {
            let Some(given_host) = host_port(given) else { return false };
            let under = |h: &str| match_type.unwrap_or(0) == 0 && given_host.ends_with(&format!(".{h}"));
            stored.as_deref().is_some_and(|h| h == given_host || under(h)) || uri == given_host || under(uri)
        }
        2 => given.as_str().starts_with(uri),
        3 if given.path() == "/" => given.as_str().trim_end_matches('/') == uri.trim_end_matches('/'),
        3 => given.as_str() == uri,
        4 => {
            use regex_automata::meta::Regex;
            let rx = Regex::builder().configure(Regex::config().nfa_size_limit(Some(REGEX_NFA_LIMIT))).build(uri);
            rx.is_ok_and(|rx| rx.is_match(given.as_str()))
        }
        _ => false,
    }
}

/// Open the item `id`. It is dropped (and wiped) by the caller before the reply is sent.
fn item_of(vault: &UnlockedVault, id: &str) -> Result<Item, AgentError> {
    let cipher = ciphers(&vault.sync).find(|c| c.get("id").and_then(Value::as_str) == Some(id));
    let cipher = cipher.ok_or(AgentError::NotFound)?;
    open(cipher, vault).map_err(|e| {
        tracing::warn!(id, "the item cannot be read: {e:?}");
        AgentError::Internal
    })
}

fn text(t: &Text) -> Option<&str> {
    t.as_deref().map(String::as_str)
}

/// The scalar properties of an item's type part: the JSON key, the name `--field` uses, the value.
fn props(item: &Item) -> Vec<(&'static str, &'static str, &Text)> {
    match &item.data {
        Data::Login(l) => {
            vec![("username", "user", &l.username), ("password", "password", &l.password), ("totp", "totp", &l.totp)]
        }
        Data::Card(c) => vec![
            ("cardholderName", "cardholder", &c.cardholder_name),
            ("brand", "brand", &c.brand),
            ("number", "number", &c.number),
            ("expMonth", "exp-month", &c.exp_month),
            ("expYear", "exp-year", &c.exp_year),
            ("code", "cvv", &c.code),
        ],
        Data::Identity(i) => vec![
            ("title", "title", &i.title),
            ("firstName", "first-name", &i.first_name),
            ("middleName", "middle-name", &i.middle_name),
            ("lastName", "last-name", &i.last_name),
            ("address1", "address1", &i.address1),
            ("address2", "address2", &i.address2),
            ("address3", "address3", &i.address3),
            ("city", "city", &i.city),
            ("state", "state", &i.state),
            ("postalCode", "postal-code", &i.postal_code),
            ("country", "country", &i.country),
            ("company", "company", &i.company),
            ("email", "email", &i.email),
            ("phone", "phone", &i.phone),
            ("ssn", "ssn", &i.ssn),
            ("username", "username", &i.username),
            ("passportNumber", "passport-number", &i.passport_number),
            ("licenseNumber", "license-number", &i.license_number),
        ],
        Data::SshKey(k) => vec![
            ("privateKey", "private-key", &k.private_key),
            ("publicKey", "public-key", &k.public_key),
            ("fingerprint", "fingerprint", &k.fingerprint),
        ],
        Data::SecureNote | Data::Unknown => vec![],
    }
}

/// The key of the type's part in the item's JSON.
fn part_key(data: &Data) -> Option<&'static str> {
    match data {
        Data::Login(_) => Some("login"),
        Data::Card(_) => Some("card"),
        Data::Identity(_) => Some("identity"),
        Data::SshKey(_) => Some("sshKey"),
        Data::SecureNote | Data::Unknown => None,
    }
}

/// Other names `--field` accepts for a property.
const ALIASES: [(&str, &str); 2] = [("username", "user"), ("code", "cvv")];

fn full_name(i: &Identity) -> Option<Zeroizing<String>> {
    let parts: Vec<&str> = [&i.first_name, &i.middle_name, &i.last_name].into_iter().filter_map(text).collect();
    let name = parts.join(" ");
    (!name.is_empty()).then(|| Zeroizing::new(name))
}

/// What `get` prints with no `--field` (profiles.md §6), and the name of what is missing when there is none.
fn primary(item: &Item) -> (&'static str, Option<Zeroizing<String>>) {
    let own = |t: &Text| text(t).map(|v| Zeroizing::new(v.to_owned()));
    match &item.data {
        Data::Login(l) => ("password", own(&l.password)),
        Data::Card(c) => ("number", own(&c.number)),
        Data::Identity(i) => ("name", full_name(i)),
        Data::SshKey(k) => ("public-key", own(&k.public_key)),
        Data::SecureNote | Data::Unknown => ("notes", own(&item.notes)),
    }
}

/// A property by name (or its alias), `name`, `notes`, `uri` (the first).
fn builtin<'a>(item: &'a Item, name: &str) -> Option<&'a str> {
    let property = |n: &str| props(item).into_iter().find(|(_, cli, _)| *cli == n).and_then(|(_, _, v)| text(v));
    let alias = ALIASES.iter().find(|(a, _)| *a == name).map_or(name, |(_, p)| *p);
    property(name).or_else(|| property(alias)).or_else(|| match (name, &item.data) {
        ("notes", _) => text(&item.notes),
        ("name", _) => Some(item.name.as_str()),
        ("uri", Data::Login(l)) => l.uris.first().and_then(|u| text(&u.uri)),
        _ => None,
    })
}

/// What `--field name` gives: [`builtin`], else a custom field by exact name.
fn field<'a>(item: &'a Item, name: &str) -> Option<&'a str> {
    builtin(item, name)
        .or_else(|| item.fields.iter().find(|f| text(&f.name) == Some(name)).and_then(|f| text(&f.value)))
}

/// The item's custom fields' names and types, decrypting nothing else (`item::field_names`).
fn names_of(vault: &UnlockedVault, id: &str) -> Result<Vec<item::FieldName>, AgentError> {
    let cipher = ciphers(&vault.sync).find(|c| c.get("id").and_then(Value::as_str) == Some(id));
    item::field_names(cipher.ok_or(AgentError::NotFound)?, vault.keys.user(), vault.keys.orgs()).map_err(|e| {
        tracing::warn!(id, "the item's field names cannot be read: {e:?}");
        AgentError::Internal
    })
}

/// `get --list-fields`: the custom fields' names, in order; the item is not opened.
pub fn field_names(vault: &UnlockedVault, id: &str) -> Result<Reply, AgentError> {
    let names = names_of(vault, id)?.iter().filter_map(|f| text(&f.name)).map(str::to_owned).collect();
    Ok(Reply::FieldNames { names })
}

/// Whether the item `id` has a custom field of the hidden type (1) named `name`. Names and types only, so it does not
/// know whether a property of that name would answer `--field` first: it errs on the side of hiding.
pub fn hidden_field(vault: &UnlockedVault, id: &str, name: &str) -> Result<bool, AgentError> {
    Ok(names_of(vault, id)?.iter().any(|f| f.kind == 1 && text(&f.name) == Some(name)))
}

fn entry(name: &str, value: &str) -> Entry {
    Entry { name: name.to_owned(), value: Secret::new(value.to_owned()) }
}

/// Every value of the item that is present: the main value first (what `get` prints, as rbw does), then the other
/// properties, every URI, the notes, then the custom fields.
fn full(item: &Item) -> Vec<Entry> {
    let (main, value) = primary(item);
    let mut out: Vec<Entry> = value.iter().map(|v| entry(main, v)).collect();
    out.extend(
        props(item).into_iter().filter(|(_, cli, _)| *cli != main).filter_map(|(_, cli, v)| Some(entry(cli, text(v)?))),
    );
    if let Data::Login(l) = &item.data {
        out.extend(l.uris.iter().filter_map(|u| Some(entry("uri", text(&u.uri)?))));
    }
    out.extend(text(&item.notes).filter(|_| main != "notes").map(|n| entry("notes", n)));
    out.extend(item.fields.iter().filter_map(|f| Some(entry(text(&f.name).unwrap_or_default(), text(&f.value)?))));
    out
}

/// The decrypted item as JSON, in the shape of the core's vectors. Written once to count and once into a buffer of
/// exactly that size, so no growing copy of the item is left in freed memory; the buffer's text moves into the
/// reply's `Secret` without a copy.
fn raw(item: &Item) -> Secret {
    let view = RawItem(item);
    // Writing to a counter and to a `Vec` cannot fail, and the view reports no error.
    let mut count = Count(0);
    serde_json::to_writer(&mut count, &view).ok();
    let mut buf = Zeroizing::new(Vec::with_capacity(count.0));
    serde_json::to_writer(&mut *buf, &view).ok();
    Secret::new(String::from_utf8(std::mem::take(&mut *buf)).unwrap_or_default())
}

/// A writer that only counts.
struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len();
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct RawItem<'a>(&'a Item);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawField<'a> {
    name: &'a Text,
    value: &'a Text,
    #[serde(rename = "type")]
    kind: u64,
    linked_id: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawPast<'a> {
    password: &'a Text,
    last_used_date: &'a Option<String>,
}

#[derive(Serialize)]
struct RawUri<'a> {
    uri: &'a Text,
    #[serde(rename = "match")]
    match_type: Option<u64>,
}

/// The type part: its properties by JSON key, and a login's URIs.
struct RawPart<'a>(&'a Item);

impl Serialize for RawPart<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut map = ser.serialize_map(None)?;
        for (key, _, value) in props(self.0) {
            map.serialize_entry(key, value)?;
        }
        if let Data::Login(l) = &self.0.data {
            let uris: Vec<_> = l.uris.iter().map(|u| RawUri { uri: &u.uri, match_type: u.match_type }).collect();
            map.serialize_entry("uris", &uris)?;
        }
        map.end()
    }
}

impl Serialize for RawItem<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let i = self.0;
        let mut map = ser.serialize_map(None)?;
        map.serialize_entry("id", &i.id)?;
        map.serialize_entry("type", &i.kind)?;
        map.serialize_entry("name", &i.name)?;
        map.serialize_entry("notes", &i.notes)?;
        map.serialize_entry("folderId", &i.folder_id)?;
        map.serialize_entry("organizationId", &i.organization_id)?;
        map.serialize_entry("reprompt", &i.reprompt)?;
        let fields: Vec<_> = i
            .fields
            .iter()
            .map(|f| RawField { name: &f.name, value: &f.value, kind: f.kind, linked_id: f.linked_id })
            .collect();
        map.serialize_entry("fields", &fields)?;
        let past: Vec<_> =
            i.history.iter().map(|h| RawPast { password: &h.password, last_used_date: &h.last_used }).collect();
        map.serialize_entry("passwordHistory", &past)?;
        if let Some(key) = part_key(&i.data) {
            map.serialize_entry(key, &RawPart(i))?;
        }
        map.end()
    }
}

/// What `get` was asked for, after the value gate (none for `--list-fields`).
pub fn value(vault: &UnlockedVault, id: &str, select: &Select) -> Result<Reply, AgentError> {
    let item = || item_of(vault, id);
    let value = |v: &str| Reply::Value { value: Secret::new(v.to_owned()) };
    match select {
        Select::Password => {
            let (what, v) = primary(&item()?);
            v.map(|v| value(&v)).ok_or_else(|| AgentError::NoSuchField(what.to_owned()))
        }
        Select::Field(name) => field(&item()?, name).map(value).ok_or_else(|| AgentError::NoSuchField(name.clone())),
        Select::Full => Ok(Reply::Full { entries: full(&item()?) }),
        Select::Raw => Ok(Reply::Raw { json: raw(&item()?) }),
        // Names only: the item is not opened.
        Select::ListFields => field_names(vault, id),
    }
}

/// The cipher `id` as `/sync` sent it, in the trash or not: what a write is planned on.
pub fn cipher<'a>(vault: &'a UnlockedVault, id: &str) -> Option<&'a Value> {
    let all = vault.sync.get("ciphers").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    all.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(id))
}

/// The `revisionDate` of this copy of the item: the base a write of it is planned on (data model §6.5).
pub fn revision(vault: &UnlockedVault, id: &str) -> String {
    let date = cipher(vault, id).and_then(|c| c.get("revisionDate")).and_then(Value::as_str);
    date.unwrap_or_default().to_owned()
}

/// The login's TOTP key, after the value gate. An item without one is `NoSuchField("totp")`; a key that gives no
/// code says why, never what it holds.
pub fn totp(vault: &UnlockedVault, id: &str) -> Result<TotpKey, AgentError> {
    let item = item_of(vault, id)?;
    let key = match &item.data {
        Data::Login(l) => text(&l.totp),
        _ => None,
    };
    let key = key.ok_or_else(|| AgentError::NoSuchField("totp".to_owned()))?;
    TotpKey::parse(key).map_err(|e| AgentError::Totp(e.to_string()))
}

/// The namespaces whose `<ns>:id` field marks the item (data model §3), sorted, each once. Field names only.
pub fn markers(vault: &UnlockedVault, id: &str) -> Result<Vec<String>, AgentError> {
    let mut names: Vec<String> = names_of(vault, id)?
        .iter()
        .filter_map(|f| text(&f.name)?.strip_suffix(":id").filter(|ns| !ns.is_empty() && !ns.contains(':')))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// The id of the folder named exactly `name`.
pub fn folder_id(vault: &UnlockedVault, name: &str) -> Result<String, AgentError> {
    let names = folder_names(&vault.sync, vault.keys.user());
    let found = names.iter().find(|(_, n)| matches!(n, Ok(n) if *n == name)).map(|(id, _)| id.to_owned());
    found.ok_or_else(|| AgentError::NoSuchFolder(name.to_owned()))
}

/// The item's previous passwords, newest first as the server keeps them. An entry without a date says `unknown`.
pub fn history(vault: &UnlockedVault, id: &str) -> Result<Reply, AgentError> {
    let item = item_of(vault, id)?;
    let entries = item
        .history
        .iter()
        .filter_map(|h| {
            let last_used = h.last_used.clone().unwrap_or_else(|| "unknown".to_owned());
            Some(HistoryEntry { last_used, password: Secret::new(text(&h.password)?.to_owned()) })
        })
        .collect();
    Ok(Reply::History { entries })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_url_matches_a_stored_uri_by_its_match_type_as_rbw_does() {
        let at = |given: &str, uri: &str, kind: Option<u64>| matches_url(uri, kind, &url::Url::parse(given).unwrap());
        // Domain (the default): the host and its subdomains, same scheme; or a bare host stored.
        assert!(at("https://x.example.com:8443/p", "https://example.com:8443", None));
        assert!(!at("https://example.com:8443", "https://example.com", Some(0)), "the port is part of the host");
        assert!(at("https://www.example.com", "example.com", Some(0)));
        assert!(!at("https://notexample.com", "example.com", Some(0)));
        // Host: exactly the host (and port), no subdomain.
        assert!(at("https://example.com/x", "https://example.com", Some(1)));
        assert!(!at("https://www.example.com", "https://example.com", Some(1)));
        assert!(at("https://example.com", "example.com", Some(1)));
        // Starts with, exact (a bare "/" path ignores the trailing slash), regular expression, never.
        assert!(at("https://example.com/login?a=1", "https://example.com/login", Some(2)));
        assert!(!at("https://example.com/other", "https://example.com/login", Some(2)));
        assert!(at("https://example.com/", "https://example.com", Some(3)));
        assert!(at("https://example.com/a", "https://example.com/a", Some(3)));
        assert!(!at("https://example.com/a/", "https://example.com/a", Some(3)));
        assert!(at("https://example.com/a", r"^https://example\.com/", Some(4)));
        assert!(!at("https://example.com/a", "(", Some(4)), "a pattern that does not compile matches nothing");
        assert!(!at("https://example.com", "https://example.com", Some(5)));
        assert!(!at("https://example.com", "https://example.com", Some(9)), "an unknown match type matches nothing");
        // A pattern that compiles beyond the size limit matches nothing, though it would match without the limit.
        let big = format!("^https://e{}", "(?:x?)".repeat(50_000));
        let unlimited = regex_automata::meta::Regex::new(&big).unwrap();
        assert!(unlimited.is_match("https://example.com"));
        assert!(!at("https://example.com", &big, Some(4)));
        // A URL with no host matches no domain or host rule.
        assert!(!at("file:///etc/hosts", "file:///etc/hosts", Some(0)));
    }

    #[test]
    fn the_counting_writer_counts_what_it_is_given() {
        use std::io::Write;
        let mut count = Count(0);
        count.write_all(b"abc").unwrap();
        count.flush().unwrap();
        assert_eq!(count.0, 3);
    }
}
