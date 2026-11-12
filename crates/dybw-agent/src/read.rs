//! The read operations (ADR 0025). `list` and `search` show what `item::summary` decrypts (name, user, folder, type)
//! and nothing more. `get` and `history` find one item by its summary, and only after the worker's value gate
//! (a confirmation the user answered) open it, put what was asked in the reply, and drop it. Nothing is kept
//! between requests: every opened item is wiped before these functions return, and the reply carries only what was
//! asked. No function here prompts or waits.

use dybw_core::profile::UnlockedVault;
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
#[derive(Debug)]
pub struct Found {
    pub id: String,
    pub name: String,
    /// The cipher asks for the master password again (`reprompt`, a plain field): P4.3 supports that.
    pub reprompt: bool,
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

fn same(a: &str, b: &str, ignorecase: bool) -> bool {
    if ignorecase { a.to_lowercase() == b.to_lowercase() } else { a == b }
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

/// rbw's lookup, as far as a summary allows: the cipher id, else the item name; `user` and the folder narrow the
/// name matches. Several matches are `Ambiguous`, naming id, name and user only. A URL names no item here.
// TODO(core): rbw also matches a URL against an item's URIs; that needs a core summary that decrypts the URIs only.
pub fn find(vault: &UnlockedVault, q: &Lookup) -> Result<Found, AgentError> {
    let found = |(c, s): &(&Value, Summary)| Found {
        id: s.id.clone(),
        name: s.name.to_string(),
        reprompt: c.get("reprompt").and_then(Value::as_u64).is_some_and(|r| r != 0),
    };
    let rows = summaries(vault);
    if let Some(row) = rows.iter().find(|(_, s)| s.id == q.needle) {
        return Ok(found(row));
    }
    let names = q.folder.is_some().then(|| folder_names(&vault.sync, vault.keys.user()));
    let narrowed = |s: &Summary| {
        let user = q.user.as_deref().is_none_or(|u| s.user.as_deref().is_some_and(|su| same(su, u, q.ignorecase)));
        let folder = q.folder.as_deref().is_none_or(|f| {
            names.as_ref().and_then(|n| folder_of(n, s)).is_some_and(|name| same(name, f, q.ignorecase))
        });
        user && folder
    };
    let rows: Vec<_> = rows.into_iter().filter(|(_, s)| narrowed(s)).collect();
    let hits: Vec<_> = rows.iter().filter(|(_, s)| same(&s.name, &q.needle, q.ignorecase)).collect();
    match hits.as_slice() {
        [] => Err(AgentError::NotFound),
        [one] => Ok(found(one)),
        many => Err(AgentError::Ambiguous {
            candidates: many
                .iter()
                .map(|(_, s)| Candidate {
                    id: s.id.clone(),
                    name: s.name.to_string(),
                    user: s.user.as_deref().cloned(),
                })
                .collect(),
        }),
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

/// A property by name (or its alias), `name`, `notes`, `uri` (the first), else a custom field by exact name.
fn field<'a>(item: &'a Item, name: &str) -> Option<&'a str> {
    let property = |n: &str| props(item).into_iter().find(|(_, cli, _)| *cli == n).and_then(|(_, _, v)| text(v));
    let alias = ALIASES.iter().find(|(a, _)| *a == name).map_or(name, |(_, p)| *p);
    property(name)
        .or_else(|| property(alias))
        .or_else(|| match (name, &item.data) {
            ("notes", _) => text(&item.notes),
            ("name", _) => Some(item.name.as_str()),
            ("uri", Data::Login(l)) => l.uris.first().and_then(|u| text(&u.uri)),
            _ => None,
        })
        .or_else(|| item.fields.iter().find(|f| text(&f.name) == Some(name)).and_then(|f| text(&f.value)))
}

fn entry(name: &str, value: &str) -> Entry {
    Entry { name: name.to_owned(), value: Secret::new(value.to_owned()) }
}

/// Every value of the item that is present: properties, every URI, the notes, then the custom fields.
fn full(item: &Item) -> Vec<Entry> {
    let mut out: Vec<Entry> = props(item).into_iter().filter_map(|(_, cli, v)| Some(entry(cli, text(v)?))).collect();
    if let Data::Login(l) = &item.data {
        out.extend(l.uris.iter().filter_map(|u| Some(entry("uri", text(&u.uri)?))));
    }
    out.extend(text(&item.notes).map(|n| entry("notes", n)));
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

/// What `get` was asked for, after the value gate (`ListFields` needs none: names are not values).
pub fn value(vault: &UnlockedVault, id: &str, select: &Select) -> Result<Reply, AgentError> {
    let item = item_of(vault, id)?;
    let value = |v: &str| Reply::Value { value: Secret::new(v.to_owned()) };
    match select {
        Select::Password => {
            let (what, v) = primary(&item);
            v.map(|v| value(&v)).ok_or_else(|| AgentError::NoSuchField(what.to_owned()))
        }
        Select::Field(name) => field(&item, name).map(value).ok_or_else(|| AgentError::NoSuchField(name.clone())),
        Select::Full => Ok(Reply::Full { entries: full(&item) }),
        Select::Raw => Ok(Reply::Raw { json: raw(&item) }),
        Select::ListFields => Ok(Reply::FieldNames {
            names: item.fields.iter().filter_map(|f| text(&f.name)).map(str::to_owned).collect(),
        }),
    }
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
    fn the_counting_writer_counts_what_it_is_given() {
        use std::io::Write;
        let mut count = Count(0);
        count.write_all(b"abc").unwrap();
        count.flush().unwrap();
        assert_eq!(count.0, 3);
    }
}
