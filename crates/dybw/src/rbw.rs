//! The `rbw` personality: `dybw` invoked as `rbw` parses rbw 1.15's command line, sends each command as the
//! requests `dybw` sends (the same policy), and prints what rbw prints, its errors included. The clap model follows
//! rbw's `src/bin/rbw/main.rs`, the output and the error texts its `src/bin/rbw/commands.rs` (rbw 1.15.0, MIT; the
//! licence is in `rbw_completion/LICENSE-rbw`). Values are printed as rbw prints them, control characters included.

use std::io::Write;

use clap::Parser as _;
use clap::error::ErrorKind;
use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};
use zeroize::Zeroizing;

use crate::rbw_edit::{self, HELP_NOTES, HELP_PW};
use crate::{AgentCmd, Cmd, Env, Fail, ask, ask_started, charset, copy_out, done, execute, generated, parse_field};
use crate::{rbw_config, report};
use dybw_proto::{AgentError, Field, ItemSummary, Op, RbwData, RbwItem, Reply, Sealed, Secret, Select};

// Help and usage texts below are copied from rbw 1.15.0 (MIT, https://github.com/doy/rbw; see
// `rbw_completion/LICENSE-rbw`).
#[derive(Debug, clap::Args)]
pub(crate) struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display")]
    needle: String,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(name = "rbw", bin_name = "rbw", version = "1.15.0", about = "Unofficial Bitwarden CLI")]
pub(crate) enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login,

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(about = "List all entries in the local Bitwarden database", visible_alias = "ls")]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            value_delimiter = ','
        )]
        fields: Vec<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
        #[arg(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[arg(short, long, help = "List fields in this entry")]
        list_fields: bool,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            value_delimiter = ','
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the authenticator code for a given entry", visible_alias = "totp")]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
            remainder will be saved as a note."
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(long, help = "URI for the password entry", number_of_values = 1)]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(long, help = "URI for the password entry", number_of_values = 1)]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(long = "no-symbols", help = "Generate a password with no special characters")]
        no_symbols: bool,
        #[arg(long = "only-numbers", help = "Generate a password consisting of only numbers")]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Lock the password database")]
    Lock,

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(name = "gen-completions", about = "Generate completion script for the given shell")]
    GenCompletions { shell: CompletionShell },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Parser)]
pub(crate) enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show,
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Opt {
    /// The name rbw puts in front of an error.
    fn name(&self) -> &'static str {
        match self {
            Self::Config { config: Config::Show } => "config show",
            Self::Config { config: Config::Set { .. } } => "config set",
            Self::Config { config: Config::Unset { .. } } => "config unset",
            Self::Register => "register",
            Self::Login => "login",
            Self::Unlock => "unlock",
            Self::Unlocked => "unlocked",
            Self::Sync => "sync",
            Self::List { .. } => "list",
            Self::Get { .. } => "get",
            Self::Search { .. } => "search",
            Self::Code { .. } => "code",
            Self::Add { .. } => "add",
            Self::Generate { .. } => "generate",
            Self::Edit { .. } => "edit",
            Self::Remove { .. } => "remove",
            Self::History { .. } => "history",
            Self::Lock => "lock",
            Self::Purge => "purge",
            Self::StopAgent => "stop-agent",
            Self::GenCompletions { .. } => "gen-completions",
        }
    }
}

/// rbw's `ListField`: `list` and `search` fail on a name it does not know, before anything else; `--raw` is every
/// field, the URIs included (`commands.rs:1181-1217`, `1361-1369`).
fn fields(names: &[String], raw: bool) -> Result<Vec<Field>, Fail> {
    if raw {
        return Ok(vec![Field::Id, Field::Name, Field::User, Field::Folder, Field::Uri, Field::Type]);
    }
    names.iter().map(|n| parse_field(n).map_err(|_| Fail::Log(format!("unknown field {n}")))).collect()
}

/// rbw's name of an item type (`commands.rs:2182-2191`).
fn type_name(kind: &str) -> &str {
    if kind == "SshKey" { "SSH Key" } else { kind }
}

/// One `--raw` row: rbw's `DecryptedListCipher` (`commands.rs:181-190`), in its key order.
#[derive(Serialize)]
struct ListRow<'a> {
    id: &'a str,
    name: Option<&'a str>,
    user: Option<&'a str>,
    folder: Option<&'a str>,
    uris: Option<&'a [String]>,
    #[serde(rename = "type")]
    entry_type: Option<&'a str>,
}

fn list_row(i: &ItemSummary, search: bool) -> ListRow<'_> {
    let uris = i.uris.as_deref();
    ListRow {
        id: &i.id,
        name: i.name.as_deref(),
        user: i.user.as_deref(),
        folder: i.folder.as_deref(),
        uris: if search { Some(uris.unwrap_or_default()) } else { uris },
        entry_type: i.kind.as_deref().map(type_name),
    }
}

/// rbw's `print_entry_list` (`commands.rs:1426-1482`), sorted by name as rbw sorts (`1379`, `1515`). A `search` row has
/// URIs for every type (empty but for a login), a `list` row for a login only. A closed pipe ends the list quietly.
fn print_list(out: &mut dyn Write, reply: Reply, fields: &[Field], raw: bool, search: bool) -> Result<u8, Fail> {
    let Reply::Items { mut items } = reply else { return Err(Fail::Unexpected) };
    items.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    if raw {
        let rows: Vec<_> = items.iter().map(|i| list_row(i, search)).collect();
        serde_json::to_writer_pretty(&mut *out, &rows).map_err(std::io::Error::from)?;
        writeln!(out)?;
        return Ok(0);
    }
    for item in &items {
        let cell = |f: &Field| crate::cell(item, *f).map(|v| if *f == Field::Type { type_name(v) } else { v });
        let line: Vec<&str> = fields.iter().map(|f| cell(f).unwrap_or_default()).collect();
        match writeln!(out, "{}", line.join("\t")) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(0),
            written => written?,
        }
    }
    Ok(0)
}

/// How rbw names an entry in its messages: `user@needle`, a URL as the `url` crate writes it (`commands.rs:26-49`,
/// `1402-1406`).
fn desc(needle: &str, user: Option<&str>) -> String {
    let shown = match url::Url::parse(needle) {
        Ok(u) if uuid::Uuid::parse_str(needle).is_err() && u.is_special() => u.to_string(),
        _ => needle.to_owned(),
    };
    user.map_or(shown.clone(), |u| format!("{u}@{shown}"))
}

/// A failed lookup in rbw's words (`find_entry` with its context, `commands.rs:1408-1410`, `2094-2103`).
fn found(desc: &str, fail: Fail) -> Fail {
    let why = match fail {
        Fail::Agent(AgentError::NotFound) => "no entry found".to_owned(),
        Fail::Agent(AgentError::Ambiguous { candidates }) => {
            let names: Vec<String> = candidates
                .iter()
                .map(|c| c.user.as_ref().map_or_else(|| c.name.clone(), |u| format!("{u}@{}", c.name)))
                .collect();
            format!("multiple entries found: {}", names.join(", "))
        }
        other => return other,
    };
    Fail::Log(format!("couldn't find entry for '{desc}': {why}"))
}

/// The agent's errors in rbw's words where rbw has some.
fn in_rbw_words(fail: Fail) -> Fail {
    match fail {
        Fail::Agent(AgentError::Locked) => Fail::Log("agent is locked".into()),
        Fail::Agent(AgentError::NotLoggedIn) => Fail::Log("not logged in (run `rbw login`)".into()),
        Fail::Agent(AgentError::Totp(why)) => Fail::Log(why),
        other => other,
    }
}

fn expose(v: Option<&Secret>) -> Option<&str> {
    v.map(Secret::expose)
}

/// rbw's `display_short` on the item: its main value, or what it lacks.
fn short(item: &RbwItem) -> Result<Zeroizing<String>, &'static str> {
    let own = |v: Option<&Secret>, what| expose(v).map(|v| Zeroizing::new(v.to_owned())).ok_or(what);
    match &item.data {
        RbwData::Login(l) => own(l.password.as_ref(), "password"),
        RbwData::Card(c) => own(c.number.as_ref(), "card number"),
        RbwData::Identity(i) => {
            let names: Vec<&str> = [&i.title, &i.first_name, &i.middle_name, &i.last_name]
                .into_iter()
                .filter_map(|n| expose(n.as_ref()))
                .collect();
            if names.is_empty() { Err("name") } else { Ok(Zeroizing::new(names.join(" "))) }
        }
        RbwData::SecureNote => own(item.notes.as_ref(), "notes"),
        RbwData::SshKey(k) => own(k.public_key.as_ref(), "public key"),
    }
}

/// rbw's `display_long` (`commands.rs:691-854`), with its `display_field` (`2807-2812`).
fn long(item: &RbwItem, desc: &str, to: &mut dyn Write, err: &mut dyn Write) -> std::io::Result<()> {
    fn line(to: &mut dyn Write, name: &str, value: Option<&str>) -> std::io::Result<bool> {
        value.map_or(Ok(false), |v| writeln!(to, "{name}: {v}").map(|()| true))
    }
    let mut shown = match short(item) {
        Ok(v) => writeln!(to, "{}", v.as_str()).map(|()| true)?,
        Err(what) => writeln!(err, "entry for '{desc}' had no {what}").map(|()| false)?,
    };
    let fields = |to: &mut dyn Write| -> std::io::Result<bool> {
        for f in &item.fields {
            let name = f.name.as_deref().unwrap_or("(null)");
            line(to, name, Some(expose(f.value.as_ref()).unwrap_or_default()))?;
        }
        Ok(!item.fields.is_empty())
    };
    match &item.data {
        RbwData::Login(l) => {
            shown |= line(to, "Username", expose(l.username.as_ref()))?;
            shown |= line(to, "TOTP Secret", expose(l.totp.as_ref()))?;
            for u in l.uris.iter().flatten() {
                shown |= line(to, "URI", Some(u.uri.expose()))?;
                shown |= line(to, "Match type", u.match_type.and_then(match_name))?;
            }
            shown |= fields(to)?;
        }
        RbwData::Card(c) => {
            if let (Some(m), Some(y)) = (expose(c.exp_month.as_ref()), expose(c.exp_year.as_ref())) {
                shown |= line(to, "Expiration", Some(&format!("{m}/{y}")))?;
            }
            shown |= line(to, "CVV", expose(c.code.as_ref()))?;
            shown |= line(to, "Name", expose(c.cardholder_name.as_ref()))?;
            shown |= line(to, "Brand", expose(c.brand.as_ref()))?;
        }
        RbwData::Identity(i) => {
            let parts = [
                ("Address", &i.address1),
                ("Address", &i.address2),
                ("Address", &i.address3),
                ("City", &i.city),
                ("State", &i.state),
                ("Postcode", &i.postal_code),
                ("Country", &i.country),
                ("Phone", &i.phone),
                ("Email", &i.email),
                ("SSN", &i.ssn),
                ("License", &i.license_number),
                ("Passport", &i.passport_number),
                ("Username", &i.username),
            ];
            for (name, value) in parts {
                shown |= line(to, name, expose(value.as_ref()))?;
            }
        }
        // A note's notes are its main value: shown once.
        RbwData::SecureNote => return Ok(()),
        RbwData::SshKey(k) => {
            shown |= line(to, "Fingerprint", expose(k.fingerprint.as_ref()))?;
            shown |= fields(to)?;
        }
    }
    if let Some(notes) = &item.notes {
        if shown {
            writeln!(to)?;
        }
        writeln!(to, "{}", notes.expose())?;
    }
    Ok(())
}

/// rbw's name of a URI match type (`src/api.rs:34-48`).
fn match_name(n: u64) -> Option<&'static str> {
    ["domain", "host", "starts_with", "exact", "regular_expression", "never"].get(usize::try_from(n).ok()?).copied()
}

/// The item as rbw's `--raw` writes it: `DecryptedCipher` with its `data` untagged (`commands.rs:338-348`, `997-1003`).
struct Json<'a>(&'a RbwItem);

impl Serialize for Json<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        struct Data<'a>(&'a RbwData);
        impl Serialize for Data<'_> {
            fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
                match self.0 {
                    RbwData::Login(l) => l.serialize(ser),
                    RbwData::Card(c) => c.serialize(ser),
                    RbwData::Identity(i) => i.serialize(ser),
                    RbwData::SecureNote => ser.serialize_unit(),
                    RbwData::SshKey(k) => k.serialize(ser),
                }
            }
        }
        let i = self.0;
        let mut s = ser.serialize_struct("DecryptedCipher", 7)?;
        s.serialize_field("id", &i.id)?;
        s.serialize_field("folder", &i.folder)?;
        s.serialize_field("name", &i.name)?;
        s.serialize_field("data", &Data(&i.data))?;
        s.serialize_field("fields", &i.fields)?;
        s.serialize_field("notes", &i.notes)?;
        s.serialize_field("history", &i.history)?;
        s.end()
    }
}

/// What `get` selects, in rbw's order: `--list-fields`, `--raw`, `--full`, `--field`, else the main value.
fn select(field: Option<String>, full: bool, raw: bool, list_fields: bool) -> Select {
    match (list_fields, raw, full, field) {
        (true, ..) => Select::ListFields,
        (_, true, ..) => Select::Raw,
        (_, _, true, _) => Select::Full,
        (.., Some(f)) => Select::Field(f),
        _ => Select::Password,
    }
}

/// rbw's `get` (`commands.rs:1387-1424`). What rbw only reports on stderr (an entry without its main value, a TOTP key
/// that gives no code) leaves the exit code 0, as in rbw. `-c` copies what would be printed (not `--raw` or `-l`,
/// which rbw prints).
fn get(
    env: &Env,
    find: FindArgs,
    select: Select,
    clipboard: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, Fail> {
    let FindArgs { needle, user, folder, ignorecase } = find;
    let desc = desc(&needle, user.as_deref());
    let profile = profile(env);
    let (field, printed) = (matches!(select, Select::Field(_)), matches!(select, Select::Raw | Select::ListFields));
    let op = Op::Get { profile, needle, user, folder, ignorecase, select, rbw: true };
    let reply = match ask_started(env, op) {
        Err(Fail::Agent(AgentError::NoValue(what))) => {
            writeln!(err, "entry for '{desc}' had no {what}")?;
            return Ok(0);
        }
        Err(Fail::Agent(AgentError::Totp(why))) if field => {
            writeln!(err, "{why}")?;
            return Ok(0);
        }
        reply => reply.map_err(|e| found(&desc, e))?,
    };
    // shortcut: a value longer than this leaves a copy in the freed buffer when it grows; rare for a password.
    let mut copied = Zeroizing::new(Vec::with_capacity(4096));
    let to: &mut dyn Write = if clipboard && !printed { &mut *copied } else { out };
    match reply {
        Reply::Value { value } => writeln!(to, "{}", value.expose())?,
        Reply::Done => {}
        Reply::FieldNames { names } => names.iter().try_for_each(|n| writeln!(to, "{n}"))?,
        Reply::RbwItem { item } if printed => {
            serde_json::to_writer_pretty(&mut *to, &Json(&item)).map_err(std::io::Error::from)?;
            writeln!(to)?;
        }
        Reply::RbwItem { item } => long(&item, &desc, to, err)?,
        _ => return Err(Fail::Unexpected),
    }
    if !copied.is_empty() {
        copy_out(env, &copied, err)?;
    }
    Ok(0)
}

/// rbw's `unlocked` (`src/bin/rbw/actions.rs:17-45`): never starts the agent.
fn unlocked(env: &Env) -> Result<u8, Fail> {
    match ask(env, Op::Status { profile: profile(env) }, false)? {
        None => Err(Fail::Log("agent not running".into())),
        Some(Reply::Status { profiles, .. }) if profiles.first().is_some_and(|p| p.unlocked) => Ok(0),
        Some(Reply::Status { .. }) => Err(Fail::Log("agent is locked".into())),
        Some(_) => Err(Fail::Unexpected),
    }
}

/// rbw's `unlock` (`commands.rs:1336-1342`): log in first when the profile is not logged in.
fn unlock(env: &Env) -> Result<u8, Fail> {
    let Reply::Status { profiles, .. } = ask_started(env, Op::Status { profile: profile(env) })? else {
        return Err(Fail::Unexpected);
    };
    if !profiles.first().is_some_and(|p| p.logged_in) {
        done(ask_started(env, Op::Login { profile: profile(env) })?)?;
    }
    done(ask_started(env, Op::Unlock { profile: profile(env) })?)
}

const NOTHING: &str = "the editor left nothing to save; nothing was changed";
const OTHER_TYPE: &str = "modifications are only supported for login and note entries";

/// The edited text as the values a write sends; refused when it holds nothing (nothing is written).
fn edited(text: &str, login: bool) -> Result<(Option<Sealed>, Sealed), Fail> {
    dybw_agent::rbw_view::edit_values(text, login).ok_or_else(|| Fail::Log(NOTHING.into()))
}

/// The agent's refusals of an rbw edit, in rbw's words.
fn edit_words(fail: Fail) -> Fail {
    match fail {
        Fail::Agent(AgentError::WriteRefused(code)) if code == "rbw-type" => Fail::Log(OTHER_TYPE.into()),
        Fail::Agent(AgentError::WriteRefused(code)) if code == "empty" => Fail::Log(NOTHING.into()),
        other => other,
    }
}

/// rbw's `add` (`commands.rs:1558-1655`): the password and notes from the editor, sent with the write.
fn add(env: &Env, name: String, user: Option<String>, uris: Vec<String>, folder: Option<String>) -> Result<u8, Fail> {
    let text = rbw_edit::edit(env, "", HELP_PW)?;
    let (password, notes) = edited(&text, true)?;
    let notes = Some(notes).filter(|n| !n.expose().is_empty());
    let op = Op::Add { profile: profile(env), name, user, uris, folder, ask: vec![], password, notes };
    done(ask_started(env, op)?)
}

/// rbw's `edit` (`commands.rs:1753-1876`). With stdin not a terminal, its text goes to the agent, which splits it by
/// the item's type: no value is read. Otherwise the current password and notes (one read through the gate, which
/// says why) are the editor's text, and the new ones are written to that item, by its id.
fn edit(env: &Env, find: FindArgs) -> Result<u8, Fail> {
    let FindArgs { needle, user, folder, ignorecase } = find;
    let desc = desc(&needle, user.as_deref());
    let profile = profile(env);
    if !env.stdin_tty {
        let mut text = (env.stdin)().map_err(|e| Fail::Log(format!("failed to read from stdin: {e}")))?;
        let text = Some(Sealed::new(std::mem::take(&mut *text)));
        let op = Op::Edit { profile, needle, user, folder, ask: vec![], ignorecase, password: None, notes: None, text };
        return done(ask_started(env, op).map_err(|e| edit_words(found(&desc, e)))?);
    }
    let read =
        Op::Get { profile: profile.clone(), needle, user, folder, ignorecase, select: Select::EditText, rbw: true };
    let Reply::RbwItem { item } = ask_started(env, read).map_err(|e| edit_words(found(&desc, e)))? else {
        return Err(Fail::Unexpected);
    };
    let mut text = Zeroizing::new(String::new());
    let (help, login) = match &item.data {
        RbwData::Login(l) => {
            text.push_str(expose(l.password.as_ref()).unwrap_or_default());
            text.push('\n');
            if let Some(notes) = &item.notes {
                text.push('\n');
                text.push_str(notes.expose());
                text.push('\n');
            }
            (HELP_PW, true)
        }
        RbwData::SecureNote => {
            text.push_str(expose(item.notes.as_ref()).unwrap_or_default());
            text.push('\n');
            (HELP_NOTES, false)
        }
        _ => return Err(Fail::Log(OTHER_TYPE.into())),
    };
    let id = item.id.clone();
    drop(item);
    let new = rbw_edit::edit(env, &text, help)?;
    drop(text);
    let (password, notes) = edited(&new, login)?;
    // The item the user was asked about, by its id: the needle is not looked up again.
    let op = Op::Edit {
        profile,
        needle: id,
        user: None,
        folder: None,
        ask: vec![],
        ignorecase: false,
        password,
        notes: Some(notes),
        text: None,
    };
    done(ask_started(env, op)?)
}

/// rbw's `gen-completions`: clap's script for the model, then rbw's own additions for bash, fish and zsh.
pub(crate) fn completions(shell: CompletionShell, out: &mut dyn Write) -> Result<(), Fail> {
    use clap::CommandFactory as _;
    use clap_complete::Shell;
    let mut cmd = Opt::command();
    match shell {
        CompletionShell::Bash => clap_complete::generate(Shell::Bash, &mut cmd, "rbw", out),
        CompletionShell::Fish => clap_complete::generate(Shell::Fish, &mut cmd, "rbw", out),
        CompletionShell::Zsh => clap_complete::generate(Shell::Zsh, &mut cmd, "rbw", out),
        CompletionShell::Powershell => clap_complete::generate(Shell::PowerShell, &mut cmd, "rbw", out),
        CompletionShell::Elvish => clap_complete::generate(Shell::Elvish, &mut cmd, "rbw", out),
        CompletionShell::Nushell => clap_complete::generate(clap_complete_nushell::Nushell, &mut cmd, "rbw", out),
        CompletionShell::Fig => clap_complete::generate(clap_complete_fig::Fig, &mut cmd, "rbw", out),
    }
    let extra = match shell {
        CompletionShell::Bash => include_str!("rbw_completion/rbw.bash"),
        CompletionShell::Fish => include_str!("rbw_completion/rbw.fish"),
        CompletionShell::Zsh => include_str!("rbw_completion/rbw.zsh"),
        _ => return Ok(()),
    };
    // rbw's `println!`.
    Ok(writeln!(out, "{extra}")?)
}

/// The profile of the shim: `RBW_PROFILE`, else the agent's default. `DYBW_PROFILE` is not read.
fn profile(env: &Env) -> Option<String> {
    (env.var)("RBW_PROFILE").and_then(|v| v.into_string().ok()).filter(|v| !v.is_empty())
}

/// Run one `rbw` command: rbw's output here, the commands whose output is `dybw`'s (none) through `execute`.
fn run_opt(opt: Opt, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> Result<u8, Fail> {
    let profile = profile(env);
    let cmd = match opt {
        Opt::Config { config } => {
            return match config {
                Config::Show => rbw_config::show(env, profile.as_deref(), out),
                Config::Set { key, value } => rbw_config::set(env, profile.as_deref(), &key, &value, err),
                Config::Unset { key } => rbw_config::unset(env, profile.as_deref(), &key, err),
            };
        }
        Opt::Purge => return done(ask_started(env, Op::Purge { profile })?),
        Opt::GenCompletions { shell } => {
            completions(shell, out)?;
            return Ok(0);
        }
        // The API key is the only login there is: `register` and `login` are the same step.
        Opt::Register | Opt::Login => Cmd::Login,
        Opt::Unlock => return unlock(env),
        Opt::Unlocked => return unlocked(env),
        Opt::Sync => Cmd::Sync { all: false },
        Opt::Lock => Cmd::Lock { all: false },
        Opt::StopAgent => Cmd::Agent { command: AgentCmd::Stop },
        Opt::List { fields: names, raw } => {
            let fields = fields(&names, raw)?;
            let reply = ask_started(env, Op::List { profile, fields: fields.clone(), folder: None })?;
            return print_list(out, reply, &fields, raw, false);
        }
        Opt::Search { term, fields: names, folder, raw } => {
            let fields = fields(&names, raw)?;
            let reply = ask_started(env, Op::Search { profile, term, folder, fields: fields.clone() })?;
            return print_list(out, reply, &fields, raw, true);
        }
        Opt::Get { find_args, field, full, raw, clipboard, list_fields } => {
            return get(env, find_args, select(field, full, raw, list_fields), clipboard, out, err);
        }
        Opt::Code { find_args: FindArgs { needle, user, folder, ignorecase }, clipboard } => {
            let desc = desc(&needle, user.as_deref());
            let op = Op::Code { profile, needle, user, folder, ignorecase, next: false };
            let code = match ask_started(env, op).map_err(|e| found(&desc, e))? {
                Reply::Code { code, .. } => code,
                _ => return Err(Fail::Unexpected),
            };
            if clipboard {
                copy_out(env, code.expose().as_bytes(), err)?;
            } else {
                writeln!(out, "{}", code.expose())?;
            }
            return Ok(0);
        }
        Opt::Add { name, user, uri, folder } => return add(env, name, user, uri, folder),
        Opt::Edit { find_args } => return edit(env, find_args),
        Opt::Remove { find_args: FindArgs { needle, user, folder, ignorecase } } => {
            let desc = desc(&needle, user.as_deref());
            let op = Op::Remove { profile, needle, user, folder, ignorecase };
            return done(ask_started(env, op).map_err(|e| found(&desc, e))?);
        }
        Opt::History { find_args: FindArgs { needle, user, folder, ignorecase } } => {
            let desc = desc(&needle, user.as_deref());
            let op = Op::History { profile, needle, user, folder, ignorecase };
            let Reply::History { entries } = ask_started(env, op).map_err(|e| found(&desc, e))? else {
                return Err(Fail::Unexpected);
            };
            entries.iter().try_for_each(|e| writeln!(out, "{}: {}", e.last_used, e.password.expose()))?;
            return Ok(0);
        }
        // rbw prints the password first, then saves it as a new login when given a name (`commands.rs:1657-1751`):
        // made here and sent with the write, which the user confirms.
        Opt::Generate { len, name, user, uri, folder, no_symbols, only_numbers, nonconfusables, diceware } => {
            let length = u32::try_from(len).map_err(|_| Fail::Log("the length is too large".into()))?;
            let mut password = generated(charset(no_symbols, only_numbers, nonconfusables, diceware), length)?;
            writeln!(out, "{}", password.as_str())?;
            let Some(name) = name else { return Ok(0) };
            let password = Some(Sealed::new(std::mem::take(&mut *password)));
            let op = Op::Add { profile, name, user, uris: uri, folder, ask: vec![], password, notes: None };
            return done(ask_started(env, op)?);
        }
    };
    execute(cmd, profile, env, out, err)
}

/// Run one `rbw` command line; the return value is the exit code (2 for a usage error, as rbw).
pub fn run<I, T>(args: I, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let opt = match Opt::try_parse_from(args) {
        Ok(opt) => opt,
        Err(e) => {
            let shown = e.render();
            return if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let _ = write!(out, "{shown}");
                0
            } else {
                let _ = write!(err, "{shown}");
                2
            };
        }
    };
    let name = opt.name();
    match run_opt(opt, env, out, err) {
        Ok(code) => code,
        // Ended by a signal held off while a secret file existed: the shell's code for it.
        Err(Fail::Signal(sig)) => u8::try_from(128 + sig).unwrap_or(1),
        Err(fail) => {
            let fail = match fail {
                // rbw's word for a code of a login without a key (`commands.rs:1543-1553`).
                Fail::Agent(AgentError::NoSuchField(f)) if name == "code" && f == "totp" => {
                    Fail::Log("entry does not contain a totp secret".into())
                }
                other => in_rbw_words(other),
            };
            report(err, &format!("rbw {name}"), &fail);
            1
        }
    }
}
