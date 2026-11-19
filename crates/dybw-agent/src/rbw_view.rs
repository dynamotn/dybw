//! rbw 1.15's view of one item, for the `rbw` shim: what its `get` prints, how its `--field` resolves, what its
//! `--list-fields` names, and its `DecryptedCipher` for `--full` and `--raw`. From rbw 1.15.0
//! `src/bin/rbw/commands.rs` (MIT): `Field::from_str` 89-132, `display_short` 351-409, `display_field` 411-689,
//! `display_fields_list` 857-995, `decrypt_cipher` 2300-2627, `DecryptedField`'s type names 1075-1095.
//!
//! Every function here works on an item the caller has already passed through the value gate, except
//! [`field_list`] (names only, as `--list-fields` is) and [`custom_kind`] (names and types only).

use dybw_core::totp::TotpKey;
use dybw_core::vault::item::{Data, FieldName, Item, Text};
use dybw_proto::{
    AgentError, RbwCard, RbwData, RbwField, RbwIdentity, RbwItem, RbwLogin, RbwPast, RbwSshKey, RbwUri, Secret,
};
use serde_json::Value;
use zeroize::Zeroizing;

fn text(t: &Text) -> Option<&str> {
    t.as_deref().map(String::as_str)
}

fn own(t: &Text) -> Option<Zeroizing<String>> {
    text(t).map(|v| Zeroizing::new(v.to_owned()))
}

fn joined<'a>(parts: impl Iterator<Item = &'a str>, by: &str) -> Zeroizing<String> {
    Zeroizing::new(parts.collect::<Vec<_>>().join(by))
}

/// rbw's `display_short`: the main value of the item, or what it lacks (rbw prints "entry for ... had no <what>").
pub fn short(item: &Item) -> Result<Zeroizing<String>, AgentError> {
    let lacks = |what: &str| AgentError::NoValue(what.to_owned());
    match &item.data {
        Data::Login(l) => own(&l.password).ok_or_else(|| lacks("password")),
        Data::Card(c) => own(&c.number).ok_or_else(|| lacks("card number")),
        Data::Identity(i) => {
            let mut names = [&i.title, &i.first_name, &i.middle_name, &i.last_name].into_iter().filter_map(text);
            let first = names.next().ok_or_else(|| lacks("name"))?;
            Ok(joined(std::iter::once(first).chain(names), " "))
        }
        Data::SshKey(k) => own(&k.public_key).ok_or_else(|| lacks("public key")),
        // rbw has no other type; one a newer server sends is shown as a note.
        Data::SecureNote | Data::Unknown => own(&item.notes).ok_or_else(|| lacks("notes")),
    }
}

/// The names `--field` takes for a login's own parts (rbw parses the lowercased name; any other is a custom field).
const LOGIN_PARTS: [&str; 10] =
    ["notes", "note", "username", "user", "password", "totp", "code", "uris", "urls", "sites"];

/// Whether `--field name` of a login reads its password or TOTP key.
pub fn login_secret(name: &str) -> bool {
    matches!(name.to_lowercase().as_str(), "password" | "totp" | "code")
}

/// The type of the custom field `--field name` of a login reads, from the names and types only; `None` when it
/// names one of the login's own parts, or no field.
pub fn custom_kind(names: &[FieldName], name: &str) -> Option<u64> {
    let f = name.to_lowercase();
    if LOGIN_PARTS.contains(&f.as_str()) {
        return None;
    }
    names.iter().find(|n| text(&n.name).is_some_and(|n| n.to_lowercase().contains(&f))).map(|n| n.kind)
}

/// rbw's fallback for a name that is none of the type's parts: the first custom field whose name holds it, ignoring
/// case; its value, or empty.
fn custom(item: &Item, f: &str) -> Option<Zeroizing<String>> {
    let hit = item.fields.iter().find(|fl| text(&fl.name).is_some_and(|n| n.to_lowercase().contains(f)))?;
    Some(own(&hit.value).unwrap_or_default())
}

/// The TOTP code of `key` at `now` (Unix seconds); rbw prints why a key gives none.
fn code(key: &str, now: u64) -> Result<Zeroizing<String>, AgentError> {
    let key = TotpKey::parse(key).map_err(|e| AgentError::Totp(e.to_string()))?;
    Ok(Zeroizing::new(key.generate(now).code().to_owned()))
}

/// What rbw's `get --field name` prints: `Ok(None)` when rbw prints nothing (a part the item lacks, no such field).
/// `now` makes a login's `totp` a code, as rbw does.
pub fn field(item: &Item, name: &str, now: u64) -> Result<Option<Zeroizing<String>>, AgentError> {
    let f = name.to_lowercase();
    let f = f.as_str();
    let notes = matches!(f, "notes" | "note");
    let value = match &item.data {
        Data::Login(l) => match f {
            "password" => return short(item).map(Some),
            "totp" | "code" => return text(&l.totp).map(|k| code(k, now)).transpose(),
            "username" | "user" => own(&l.username),
            "uris" | "urls" | "sites" => Some(joined(l.uris.iter().filter_map(|u| text(&u.uri)), "\n")),
            _ if notes => own(&item.notes),
            _ => custom(item, f),
        },
        Data::Card(c) => match f {
            "number" | "card" => return short(item).map(Some),
            "exp" => text(&c.exp_month).zip(text(&c.exp_year)).map(|(m, y)| Zeroizing::new(format!("{m}/{y}"))),
            "exp_month" | "month" => own(&c.exp_month),
            "exp_year" | "year" => own(&c.exp_year),
            "cvv" => own(&c.code),
            "name" | "cardholder" | "cardholder_name" => own(&c.cardholder_name),
            "brand" | "type" => own(&c.brand),
            _ if notes => own(&item.notes),
            _ => custom(item, f),
        },
        Data::Identity(i) => match f {
            "name" => return short(item).map(Some),
            "email" => own(&i.email),
            "address" => {
                let mut lines = [&i.address1, &i.address2, &i.address3].into_iter().filter_map(text).peekable();
                lines.peek().is_some().then(|| joined(lines, "\n"))
            }
            "city" => own(&i.city),
            "state" => own(&i.state),
            "postcode" | "zipcode" | "zip" => own(&i.postal_code),
            "country" => own(&i.country),
            "phone" => own(&i.phone),
            "ssn" => own(&i.ssn),
            "license" => own(&i.license_number),
            "passport" => own(&i.passport_number),
            "username" | "user" => own(&i.username),
            _ if notes => own(&item.notes),
            _ => custom(item, f),
        },
        Data::SshKey(k) => match f {
            "public_key" => return short(item).map(Some),
            "fingerprint" => own(&k.fingerprint),
            "private_key" => own(&k.private_key),
            _ if notes => own(&item.notes),
            _ => custom(item, f),
        },
        Data::SecureNote | Data::Unknown if notes => return short(item).map(Some),
        Data::SecureNote | Data::Unknown => custom(item, f),
    };
    Ok(value)
}

/// rbw's `display_fields_list`, decrypting the custom fields' names only: a part of the item's type is named when the
/// cipher holds a value for it (an encrypted string, present without decrypting it). A login always has `uris`, as in
/// rbw. shortcut: a blob item (ADR 0021) shows its custom fields only, as its parts are inside the blob.
pub fn field_list(cipher: &Value, kind: u64, names: &[FieldName]) -> Vec<String> {
    let has = |part: &str, key: &str| cipher.get(part).and_then(|p| p.get(key)).is_some_and(|v| !v.is_null());
    let any = |part: &str, keys: &[&str]| keys.iter().any(|k| has(part, k));
    let parts: Vec<(&str, bool)> = match kind {
        1 => vec![
            ("username", has("login", "username")),
            ("totp", has("login", "totp")),
            ("uris", true),
            ("password", has("login", "password")),
        ],
        3 => vec![
            ("number", has("card", "number")),
            ("exp_month", has("card", "expMonth")),
            ("exp_year", has("card", "expYear")),
            ("cvv", has("card", "code")),
            ("cardholder", has("card", "cardholderName")),
            ("brand", has("card", "brand")),
        ],
        4 => {
            let one = |key: &str| has("identity", key);
            vec![
                ("name", any("identity", &["title", "firstName", "middleName", "lastName"])),
                ("email", one("email")),
                ("address", any("identity", &["address1", "address2", "address3"])),
                ("city", one("city")),
                ("state", one("state")),
                ("postcode", one("postalCode")),
                ("country", one("country")),
                ("phone", one("phone")),
                ("ssn", one("ssn")),
                ("license", one("licenseNumber")),
                ("passport", one("passportNumber")),
                ("username", one("username")),
            ]
        }
        5 => vec![("fingerprint", has("sshKey", "keyFingerprint")), ("public_key", has("sshKey", "publicKey"))],
        _ => vec![],
    };
    let notes = cipher.get("notes").is_some_and(|v| !v.is_null());
    let own_parts = parts.into_iter().chain([("notes", notes)]).filter(|(_, on)| *on).map(|(n, _)| n.to_owned());
    own_parts.chain(names.iter().filter_map(|n| text(&n.name)).map(str::to_owned)).collect()
}

/// rbw's name of a custom field's type.
fn field_type(kind: u64) -> Option<String> {
    let name = match kind {
        0 => "text",
        1 => "hidden",
        2 => "boolean",
        3 => "linked",
        _ => return None,
    };
    Some(name.to_owned())
}

/// The item as rbw's `DecryptedCipher`; `folder` is its folder's name. A history entry without a date says `unknown`
/// (as `dybw history`); one without a password is left out.
pub fn item(item: &Item, folder: Option<String>) -> RbwItem {
    let s = |t: &Text| text(t).map(|v| Secret::new(v.to_owned()));
    let data = match &item.data {
        Data::Login(l) => RbwData::Login(RbwLogin {
            username: s(&l.username),
            password: s(&l.password),
            totp: s(&l.totp),
            uris: Some(
                l.uris.iter().filter_map(|u| Some(RbwUri { uri: s(&u.uri)?, match_type: u.match_type })).collect(),
            ),
        }),
        Data::Card(c) => RbwData::Card(RbwCard {
            cardholder_name: s(&c.cardholder_name),
            number: s(&c.number),
            brand: s(&c.brand),
            exp_month: s(&c.exp_month),
            exp_year: s(&c.exp_year),
            code: s(&c.code),
        }),
        Data::Identity(i) => RbwData::Identity(Box::new(RbwIdentity {
            title: s(&i.title),
            first_name: s(&i.first_name),
            middle_name: s(&i.middle_name),
            last_name: s(&i.last_name),
            address1: s(&i.address1),
            address2: s(&i.address2),
            address3: s(&i.address3),
            city: s(&i.city),
            state: s(&i.state),
            postal_code: s(&i.postal_code),
            country: s(&i.country),
            phone: s(&i.phone),
            email: s(&i.email),
            ssn: s(&i.ssn),
            license_number: s(&i.license_number),
            passport_number: s(&i.passport_number),
            username: s(&i.username),
        })),
        Data::SshKey(k) => RbwData::SshKey(RbwSshKey {
            public_key: s(&k.public_key),
            fingerprint: s(&k.fingerprint),
            private_key: s(&k.private_key),
        }),
        Data::SecureNote | Data::Unknown => RbwData::SecureNote,
    };
    RbwItem {
        id: item.id.clone(),
        folder,
        name: item.name.to_string(),
        data,
        fields: item
            .fields
            .iter()
            .map(|f| RbwField { name: text(&f.name).map(str::to_owned), value: s(&f.value), ty: field_type(f.kind) })
            .collect(),
        notes: s(&item.notes),
        history: item
            .history
            .iter()
            .filter_map(|h| {
                let last_used_date = h.last_used.clone().unwrap_or_else(|| "unknown".to_owned());
                Some(RbwPast { last_used_date, password: s(&h.password)? })
            })
            .collect(),
    }
}
