//! The `dybw` command line: parse, ask the agent, print. Values are printed straight from the reply's `Secret`
//! and dropped; nothing here logs or keeps one.

#![forbid(unsafe_code)]

mod client;

use std::io::Write;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};
use dybw_proto::{AgentError, Field, ItemSummary, Op, Reply, Select, Target};
use serde_json::{Map, Value};

pub use client::{Env, Error as ClientError, START_WAIT};

/// Command line client for the dybw agent.
// TODO(P4.4): dispatch on argv[0] here (the git-credential and ssh-askpass personalities) before parsing.
#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// The profile to use (default: `DYBW_PROFILE`, else the agent's default profile).
    #[arg(short, long, global = true)]
    profile: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Store the API key of the profile.
    Login,
    /// Unlock the vault (asks for the master password).
    Unlock,
    /// Exit 0 when the profile is unlocked, 1 when not.
    Unlocked,
    /// Lock the vault.
    Lock {
        #[arg(long)]
        all: bool,
    },
    /// Show the state of the profile.
    Status,
    /// Fetch the vault from the server now.
    Sync {
        #[arg(long)]
        all: bool,
    },
    /// List the items.
    List {
        #[command(flatten)]
        shape: Shape,
        /// JSON instead of tab-separated text.
        #[arg(long)]
        raw: bool,
    },
    /// List the items whose name or user contains the term.
    Search {
        term: String,
        #[command(flatten)]
        shape: Shape,
    },
    /// Print a value of one item.
    Get {
        /// The item: a name or a cipher id.
        item: String,
        user: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(short, long)]
        ignorecase: bool,
        /// Print this field (user, totp, notes, cvv, a custom field name, ...).
        #[arg(short = 'f', long, group = "select")]
        field: Option<String>,
        /// Print the password, then the notes and fields.
        #[arg(long, group = "select")]
        full: bool,
        /// Print the decrypted item as JSON.
        #[arg(long, group = "select")]
        raw: bool,
        /// Print the names of the custom fields.
        #[arg(short = 'l', long, group = "select")]
        list_fields: bool,
    },
    /// Print the previous passwords of an item, newest first.
    History {
        item: String,
        user: Option<String>,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Talk to the agent process itself.
    Agent {
        #[command(subcommand)]
        command: AgentCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    /// Stop the agent (locks every profile).
    Stop,
}

/// What `list` and `search` show.
#[derive(Args, Debug)]
struct Shape {
    /// Comma-separated: id, name, user, folder, type.
    #[arg(long, value_delimiter = ',', value_parser = parse_field, default_value = "name")]
    fields: Vec<Field>,
    #[arg(long)]
    folder: Option<String>,
}

fn parse_field(s: &str) -> Result<Field, String> {
    match s {
        "id" => Ok(Field::Id),
        "name" => Ok(Field::Name),
        "user" => Ok(Field::User),
        "folder" => Ok(Field::Folder),
        "type" => Ok(Field::Type),
        _ => Err(format!("unknown field {s:?} (id, name, user, folder, type)")),
    }
}

/// Why a command failed. Printed as `dybw: <message>`; every failure exits 1.
#[derive(Debug, thiserror::Error)]
enum Fail {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("{}", agent_text(.0))]
    Agent(AgentError),
    /// A safety check refused the unlock; `log` names the log of the agent this command started.
    #[error("the {check} check refused the unlock; see {}", .log.as_ref().map_or("the agent log".into(), |p| p.display().to_string()))]
    Refused { check: String, log: Option<std::path::PathBuf> },
    #[error("the agent sent a reply that does not fit the request")]
    Unexpected,
    #[error("cannot write the output: {0}")]
    Output(#[from] std::io::Error),
}

fn agent_text(e: &AgentError) -> String {
    match e {
        AgentError::Prompt => "the confirmation prompt could not be shown (pinentry)".into(),
        AgentError::Denied => "denied".into(),
        AgentError::Locked => "the vault is locked (run `dybw unlock`)".into(),
        AgentError::NotLoggedIn => "the profile is not logged in (run `dybw login`)".into(),
        other => other.to_string(),
    }
}

/// Send `op`; an error reply becomes a failure.
fn ask(env: &Env, op: Op, autostart: bool) -> Result<Option<Reply>, Fail> {
    match client::call(env, op, autostart)? {
        Some(Reply::Error { error: AgentError::Refused(check) }) => {
            Err(Fail::Refused { check, log: env.started_log.borrow().clone() })
        }
        Some(Reply::Error { error }) => Err(Fail::Agent(error)),
        other => Ok(other),
    }
}

/// `ask` for an op that always needs the agent.
fn ask_started(env: &Env, op: Op) -> Result<Reply, Fail> {
    ask(env, op, true).map(|r| r.unwrap_or(Reply::Done))
}

/// The profile `lock` and `sync` act on when none was named: the agent's default. `None`: no agent runs.
fn default_profile(env: &Env, profile: Option<String>, autostart: bool) -> Result<Option<String>, Fail> {
    if profile.is_some() {
        return Ok(profile);
    }
    match ask(env, Op::Status { profile: None }, autostart)? {
        Some(Reply::Status { profiles, .. }) => {
            profiles.into_iter().next().map(|p| Some(p.profile)).ok_or(Fail::Unexpected)
        }
        Some(_) => Err(Fail::Unexpected),
        None => Ok(None),
    }
}

fn execute(cli: Cli, env: &Env, out: &mut dyn Write) -> Result<u8, Fail> {
    let profile =
        cli.profile.or_else(|| (env.var)("DYBW_PROFILE").and_then(|v| v.into_string().ok()).filter(|v| !v.is_empty()));
    match cli.command {
        Cmd::Login => done(ask_started(env, Op::Login { profile })?),
        Cmd::Unlock => done(ask_started(env, Op::Unlock { profile })?),
        Cmd::Unlocked => match ask(env, Op::Status { profile }, false)? {
            // No agent, nothing unlocked.
            None => Ok(1),
            Some(Reply::Status { profiles, .. }) => Ok(u8::from(!profiles.first().is_some_and(|p| p.unlocked))),
            Some(_) => Err(Fail::Unexpected),
        },
        Cmd::Lock { all } => {
            let Some(target) = target(env, profile, all, false)? else { return Ok(0) };
            // No agent running means nothing to lock, and none is started for it.
            done(ask(env, Op::Lock { target }, false)?.unwrap_or(Reply::Done))
        }
        Cmd::Sync { all } => {
            let target = target(env, profile, all, true)?.ok_or(Fail::Unexpected)?;
            done(ask_started(env, Op::Sync { target })?)
        }
        Cmd::Status => match ask_started(env, Op::Status { profile })? {
            Reply::Status { profiles, .. } => {
                for p in profiles {
                    let logged = if p.logged_in { "logged in" } else { "not logged in" };
                    let state = if p.unlocked { "unlocked" } else { "locked" };
                    let sync = p.last_sync.map_or("-".into(), |t| t.to_string());
                    writeln!(out, "{}\t{logged}\t{state}\t{sync}", p.profile)?;
                }
                Ok(0)
            }
            _ => Err(Fail::Unexpected),
        },
        Cmd::List { shape, raw } => {
            let Shape { fields, folder } = shape;
            let reply = ask_started(env, Op::List { profile, fields: fields.clone(), folder })?;
            items(out, reply, &fields, raw)
        }
        Cmd::Search { term, shape: Shape { fields, folder } } => {
            let reply = ask_started(env, Op::Search { profile, term, folder, fields: fields.clone() })?;
            items(out, reply, &fields, false)
        }
        Cmd::Get { item, user, folder, ignorecase, field, full, raw, list_fields } => {
            let select = match (field, full, raw, list_fields) {
                (Some(f), ..) => Select::Field(f),
                (_, true, ..) => Select::Full,
                (_, _, true, _) => Select::Raw,
                (_, _, _, true) => Select::ListFields,
                _ => Select::Password,
            };
            let op = Op::Get { profile, needle: item, user, folder, ignorecase, select };
            match ask_started(env, op)? {
                Reply::Value { value } | Reply::Raw { json: value } => writeln!(out, "{}", value.expose())?,
                Reply::Full { entries } => {
                    for (i, e) in entries.iter().enumerate() {
                        match (i, e.name.as_str()) {
                            (0, _) => writeln!(out, "{}", e.value.expose())?,
                            (_, "notes") => writeln!(out, "\n{}", e.value.expose())?,
                            (_, name) => writeln!(out, "{name}: {}", e.value.expose())?,
                        }
                    }
                }
                Reply::FieldNames { names } => names.iter().try_for_each(|n| writeln!(out, "{n}"))?,
                _ => return Err(Fail::Unexpected),
            }
            Ok(0)
        }
        Cmd::History { item, user, folder } => {
            match ask_started(env, Op::History { profile, needle: item, user, folder })? {
                Reply::History { entries } => {
                    entries.iter().try_for_each(|e| writeln!(out, "{}: {}", e.last_used, e.password.expose()))?;
                    Ok(0)
                }
                _ => Err(Fail::Unexpected),
            }
        }
        // Nothing to stop when no agent runs, and none is started to be stopped.
        Cmd::Agent { command: AgentCmd::Stop } => done(ask(env, Op::StopAgent, false)?.unwrap_or(Reply::Done)),
    }
}

/// `--all`, or the named or default profile. `None`: no agent runs and `autostart` is off.
fn target(env: &Env, profile: Option<String>, all: bool, autostart: bool) -> Result<Option<Target>, Fail> {
    if all {
        return Ok(Some(Target::All));
    }
    Ok(default_profile(env, profile, autostart)?.map(Target::Profile))
}

fn done(reply: Reply) -> Result<u8, Fail> {
    if reply == Reply::Done { Ok(0) } else { Err(Fail::Unexpected) }
}

fn items(out: &mut dyn Write, reply: Reply, fields: &[Field], raw: bool) -> Result<u8, Fail> {
    let Reply::Items { items } = reply else { return Err(Fail::Unexpected) };
    if raw {
        let rows: Vec<Value> = items.iter().map(|i| json_row(i, fields)).collect();
        writeln!(out, "{}", Value::Array(rows))?;
    } else {
        for item in &items {
            let cells: Vec<String> = fields.iter().map(|f| escape(cell(item, *f).unwrap_or(""))).collect();
            writeln!(out, "{}", cells.join("\t"))?;
        }
    }
    Ok(0)
}

fn cell(item: &ItemSummary, field: Field) -> Option<&str> {
    match field {
        Field::Id => Some(&item.id),
        Field::Name => item.name.as_deref(),
        Field::User => item.user.as_deref(),
        Field::Folder => item.folder.as_deref(),
        Field::Type => item.kind.as_deref(),
    }
}

/// Control characters (tab and newline included) as `\xNN`: an item name must not forge columns, rows or terminal
/// escapes in text output.
fn escape(text: &str) -> String {
    text.chars().fold(String::new(), |mut s, c| {
        if c.is_control() {
            s.push_str(&format!("\\x{:02x}", u32::from(c)));
        } else {
            s.push(c);
        }
        s
    })
}

/// The requested fields of one item (`id` always), null when the item has none.
fn json_row(item: &ItemSummary, fields: &[Field]) -> Value {
    let mut row = Map::new();
    row.insert("id".into(), item.id.clone().into());
    for (key, field) in [("name", Field::Name), ("user", Field::User), ("folder", Field::Folder), ("type", Field::Type)]
    {
        if fields.contains(&field) {
            row.insert(key.into(), cell(item, field).map_or(Value::Null, Value::from));
        }
    }
    Value::Object(row)
}

/// Print the failure; an ambiguous lookup also lists its candidates as `id<TAB>name<TAB>user`.
fn report(err: &mut dyn Write, fail: &Fail) {
    let _ = writeln!(err, "dybw: {fail}");
    if let Fail::Agent(AgentError::Ambiguous { candidates }) = fail {
        for c in candidates {
            let user = c.user.as_deref().unwrap_or("");
            let _ = writeln!(err, "{}\t{}\t{}", escape(&c.id), escape(&c.name), escape(user));
        }
    }
}

/// Run one command line; the return value is the exit code.
pub fn run<I, T>(args: I, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version go to stdout and succeed; a usage error is a failure like any other.
            let shown = e.render();
            return if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let _ = write!(out, "{shown}");
                0
            } else {
                let _ = write!(err, "{shown}");
                1
            };
        }
    };
    match execute(cli, env, out) {
        Ok(code) => code,
        Err(fail) => {
            report(err, &fail);
            1
        }
    }
}

pub fn main() -> ExitCode {
    ExitCode::from(run(std::env::args_os(), &Env::real(), &mut std::io::stdout().lock(), &mut std::io::stderr().lock()))
}

#[cfg(test)]
mod tests;
