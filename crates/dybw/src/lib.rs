//! The `dybw` command line: parse, ask the agent, print. Values are printed straight from the reply's `Secret`
//! and dropped; nothing here logs or keeps one.

#![forbid(unsafe_code)]

mod client;
mod clip;
mod doctor;
mod rbw;
mod rbw_config;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};
use dybw_proto::{AgentError, Charset, Field, ItemSummary, Op, Part, PolicyAction, PolicyRule, Reply, Select, Target};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use clip::Copied;

pub use client::{Env, Error as ClientError, START_WAIT};

/// Command line client for the dybw agent.
// `main` dispatches on argv[0]: invoked as `rbw`, it is the rbw shim (`rbw.rs`).
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
        /// Copy to the clipboard, marked as secret, instead of printing; cleared after `clipboard_clear_seconds`
        /// if it still holds the value.
        #[arg(short = 'c', long)]
        clipboard: bool,
    },
    /// Print the previous passwords of an item, newest first.
    History {
        item: String,
        user: Option<String>,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Print the current TOTP code of a login (the key never leaves the agent).
    Code {
        item: String,
        user: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(short, long)]
        ignorecase: bool,
        /// When fewer than 5 seconds of the code are left, wait for the next one.
        #[arg(long)]
        next: bool,
        /// Copy to the clipboard, marked as secret, instead of printing.
        #[arg(short = 'c', long)]
        clipboard: bool,
    },
    /// Add a login; its password (and with `--notes` its notes) is typed in the agent's pinentry, one line each.
    Add {
        name: String,
        user: Option<String>,
        /// A URI of the login (repeatable).
        #[arg(long)]
        uri: Vec<String>,
        /// The folder; one that does not exist is created.
        #[arg(long)]
        folder: Option<String>,
        #[command(flatten)]
        ask: Ask,
    },
    /// Change an item's password (and with `--notes` its notes), typed in the agent's pinentry; the old password goes
    /// to the history.
    Edit {
        item: String,
        user: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[command(flatten)]
        ask: Ask,
    },
    /// Move an item to the trash.
    Remove {
        item: String,
        user: Option<String>,
        #[arg(long)]
        folder: Option<String>,
    },
    /// Print a new random password; with a name, the agent makes one and saves it as a new login instead, and nothing
    /// is printed (`dybw get <name>` shows it).
    Generate {
        /// Characters, or words with `--diceware`.
        length: u32,
        name: Option<String>,
        user: Option<String>,
        #[arg(long, requires = "name")]
        uri: Vec<String>,
        #[arg(long, requires = "name")]
        folder: Option<String>,
        #[arg(long, group = "charset")]
        no_symbols: bool,
        #[arg(long, group = "charset")]
        only_numbers: bool,
        /// Letters and digits that cannot be mistaken for one another.
        #[arg(long, group = "charset")]
        nonconfusables: bool,
        /// Words of the EFF large list, separated by spaces.
        #[arg(long, group = "charset")]
        diceware: bool,
    },
    /// Show or change which programs may read values (changes are confirmed in the pinentry).
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Show the audit log: who asked for which item, and what was decided (never a value).
    Audit {
        /// Only requests from AI-class and unknown callers (an unknown one may be an AI agent too).
        #[arg(long)]
        ai: bool,
        /// How many of the latest lines to show.
        #[arg(short, default_value_t = 50)]
        n: usize,
    },
    /// Check this machine: socket directory, agent, config, pinentry, policy and audit files.
    Doctor,
    /// Talk to the agent process itself.
    Agent {
        #[command(subcommand)]
        command: AgentCmd,
    },
    /// The clipboard clearer `-c` starts: the job comes on stdin.
    #[command(name = clip::CLEAR_COMMAND, hide = true)]
    ClearClipboard,
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    /// Stop the agent (locks every profile).
    Stop,
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// List the remembered programs: rule (`allow`, `allow-detached`, `deny`), program, script, hash.
    Show,
    /// Always let a program read single values, as long as it is unchanged. Not for an interpreter, a shell or a
    /// launcher: a script's "always" is given in the question and lasts for its process only.
    Allow {
        /// The program's absolute path.
        invoker: String,
        /// For the program when it runs detached (its parent exited), and only then: such a run is never offered
        /// "always" in a question.
        #[arg(long)]
        detached: bool,
    },
    /// Never let a program read values, whatever it contains; without `--script`, whatever script it runs.
    Deny {
        invoker: String,
        #[arg(long)]
        script: Option<String>,
    },
    /// Drop what is remembered for a program or a script.
    Forget { invoker: String },
}

/// Which values `add` and `edit` ask for in the pinentry: the password unless `--no-password`, the notes with
/// `--notes`.
#[derive(Args, Debug)]
struct Ask {
    /// Also ask for the notes (one line; they replace the old ones).
    #[arg(long)]
    notes: bool,
    /// Do not ask for the password.
    #[arg(long)]
    no_password: bool,
}

impl Ask {
    fn parts(&self) -> Vec<Part> {
        [(!self.no_password, Part::Password), (self.notes, Part::Notes)]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, p)| p)
            .collect()
    }
}

/// The absolute, symlink-free path the agent sees a program or script under; a relative path means nothing to it.
fn canonical(path: &str) -> Result<String, Fail> {
    let found = std::fs::canonicalize(path).map_err(|e| Fail::Log(format!("cannot find {path}: {e}")))?;
    Ok(found.to_string_lossy().into_owned())
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
    /// An error whose reason is only in the agent log (a denial, a bad configuration).
    #[error("{what} (see {})", .log.as_ref().map_or("the agent log".into(), |p| p.display().to_string()))]
    Logged { what: &'static str, log: Option<std::path::PathBuf> },
    #[error("the agent sent a reply that does not fit the request")]
    Unexpected,
    #[error("{0}")]
    Log(String),
    #[error("cannot write the output: {0}")]
    Output(#[from] std::io::Error),
    #[error("clipboard: {0}")]
    Clip(#[from] clip::Error),
}

fn agent_text(e: &AgentError) -> String {
    match e {
        AgentError::Prompt => "the confirmation prompt could not be shown (pinentry)".into(),
        AgentError::Locked => "the vault is locked (run `dybw unlock`)".into(),
        AgentError::NotLoggedIn => "the profile is not logged in (run `dybw login`)".into(),
        other => other.to_string(),
    }
}

/// A pinentry as the agent would resolve it, or why it would not.
fn pinentry_text(p: &str) -> Result<String, String> {
    dybw_agent::trust::pinentry_of(p).map_err(|e| format!("{e:#}"))
}

/// Send `op`; an error reply becomes a failure.
fn ask(env: &Env, op: Op, autostart: bool) -> Result<Option<Reply>, Fail> {
    match client::call(env, op, autostart)? {
        Some(Reply::Error { error: AgentError::Refused(check) }) => {
            Err(Fail::Refused { check, log: env.started_log.borrow().clone() })
        }
        Some(Reply::Error { error: e @ (AgentError::Denied | AgentError::Config) }) => {
            let what = if e == AgentError::Denied { "denied" } else { "the configuration is invalid" };
            Err(Fail::Logged { what, log: env.started_log.borrow().clone() })
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

fn execute(cmd: Cmd, profile: Option<String>, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> Result<u8, Fail> {
    match cmd {
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
        Cmd::Get { item, user, folder, ignorecase, field, full, raw, list_fields, clipboard } => {
            let select = match (field, full, raw, list_fields) {
                (Some(f), ..) => Select::Field(f),
                (_, true, ..) => Select::Full,
                (_, _, true, _) => Select::Raw,
                (_, _, _, true) => Select::ListFields,
                _ => Select::Password,
            };
            let op = Op::Get { profile, needle: item, user, folder, ignorecase, select };
            let reply = ask_started(env, op)?;
            // shortcut: a value longer than this leaves a copy in the freed buffer when it grows; rare for a password.
            let mut copied = Zeroizing::new(Vec::with_capacity(4096));
            let to: &mut dyn Write = if clipboard { &mut *copied } else { out };
            match reply {
                Reply::Value { value } | Reply::Raw { json: value } => writeln!(to, "{}", value.expose())?,
                Reply::Full { entries } => {
                    for (i, e) in entries.iter().enumerate() {
                        match (i, e.name.as_str()) {
                            (0, _) => writeln!(to, "{}", e.value.expose())?,
                            (_, "notes") => writeln!(to, "\n{}", e.value.expose())?,
                            (_, name) => writeln!(to, "{}: {}", escape(name), e.value.expose())?,
                        }
                    }
                }
                Reply::FieldNames { names } => names.iter().try_for_each(|n| writeln!(to, "{}", escape(n)))?,
                _ => return Err(Fail::Unexpected),
            }
            if clipboard {
                copy_out(env, &copied, err)?;
            }
            Ok(0)
        }
        Cmd::History { item, user, folder } => {
            match ask_started(env, Op::History { profile, needle: item, user, folder })? {
                Reply::History { entries } => {
                    entries
                        .iter()
                        .try_for_each(|e| writeln!(out, "{}: {}", escape(&e.last_used), e.password.expose()))?;
                    Ok(0)
                }
                _ => Err(Fail::Unexpected),
            }
        }
        Cmd::Code { item, user, folder, ignorecase, next, clipboard } => {
            let op = Op::Code { profile, needle: item, user, folder, ignorecase, next };
            let Reply::Code { code, .. } = ask_started(env, op)? else { return Err(Fail::Unexpected) };
            if clipboard {
                copy_out(env, code.expose().as_bytes(), err)?;
            } else {
                writeln!(out, "{}", code.expose())?;
            }
            Ok(0)
        }
        Cmd::Add { name, user, uri, folder, ask } => {
            done(ask_started(env, Op::Add { profile, name, user, uris: uri, folder, ask: ask.parts() })?)
        }
        Cmd::Edit { item, user, folder, ask } => {
            done(ask_started(env, Op::Edit { profile, needle: item, user, folder, ask: ask.parts() })?)
        }
        Cmd::Remove { item, user, folder } => {
            done(ask_started(env, Op::Remove { profile, needle: item, user, folder })?)
        }
        Cmd::Generate { length, name, user, uri, folder, no_symbols, only_numbers, nonconfusables, diceware } => {
            let charset = match (no_symbols, only_numbers, nonconfusables, diceware) {
                (true, ..) => Charset::NoSymbols,
                (_, true, ..) => Charset::Numbers,
                (_, _, true, _) => Charset::Nonconfusables,
                (.., true) => Charset::Diceware,
                _ => Charset::All,
            };
            match name {
                // Made and kept by the agent: the password never crosses the socket, so there is none to print.
                Some(name) => {
                    done(ask_started(env, Op::Generate { profile, name, user, uris: uri, folder, length, charset })?)
                }
                None => {
                    let password = dybw_agent::pwgen::generate(&dybw_agent::pwgen::OsRandom, charset, length)
                        .map_err(|e| Fail::Log(e.to_string()))?;
                    writeln!(out, "{}", password.as_str())?;
                    Ok(0)
                }
            }
        }
        Cmd::Policy { command } => {
            let action = match command {
                PolicyCmd::Show => PolicyAction::Show,
                PolicyCmd::Allow { invoker, detached } => {
                    PolicyAction::Allow { invoker: canonical(&invoker)?, script: None, detached }
                }
                PolicyCmd::Deny { invoker, script } => PolicyAction::Deny {
                    invoker: canonical(&invoker)?,
                    script: script.as_deref().map(canonical).transpose()?,
                },
                PolicyCmd::Forget { invoker } => PolicyAction::Forget { invoker },
            };
            let shown = action == PolicyAction::Show;
            match ask_started(env, Op::Policy { profile, action })? {
                Reply::Policy { entries } if shown => {
                    for e in entries {
                        let rule = match (e.rule, e.detached) {
                            (PolicyRule::Allow, false) => "allow",
                            (PolicyRule::Allow, true) => "allow-detached",
                            (PolicyRule::Deny, _) => "deny",
                        };
                        let script = e.script.as_deref().unwrap_or("");
                        writeln!(out, "{rule}\t{}\t{}\t{}", escape(&e.exe), escape(script), escape(&e.hash))?;
                    }
                    Ok(0)
                }
                reply if !shown => done(reply),
                _ => Err(Fail::Unexpected),
            }
        }
        Cmd::Audit { ai, n } => audit(env, ai, n, out),
        Cmd::Doctor => {
            let me = doctor::home_of(env)
                .and_then(|home| dybw_agent::caller::this_process(&dybw_agent::paths::harnesses_path(&home)));
            Ok(doctor::run(env, profile.as_deref(), me, &pinentry_text, out)?)
        }
        // Nothing to stop when no agent runs, and none is started to be stopped.
        Cmd::Agent { command: AgentCmd::Stop } => done(ask(env, Op::StopAgent, false)?.unwrap_or(Reply::Done)),
        Cmd::ClearClipboard => clear_later(env),
    }
}

/// Copy the output (its last newline dropped) and start the clearer. The delay is read first: a bad config leaves
/// nothing on the clipboard.
fn copy_out(env: &Env, text: &[u8], err: &mut dyn Write) -> Result<(), Fail> {
    let config = dybw_agent::paths::config_path(&doctor::home_of(env).ok_or_else(no_home)?);
    let seconds = dybw_agent::config::Config::load(&config)
        .and_then(|c| c.clipboard_clear_seconds())
        .map_err(|e| Fail::Log(format!("{e:#}")))?;
    let Copied { token, marked } = (env.clip.copy)(text.strip_suffix(b"\n").unwrap_or(text))?;
    if !marked {
        let _ =
            writeln!(err, "dybw: note: this clipboard cannot mark the copy as secret; a clipboard manager may keep it");
    }
    // No clearer, no copy left behind.
    (env.clip.spawn)(&clip::job(seconds, &token)).map_err(|e| {
        let _ = (env.clip.clear)(&token);
        Fail::Log(format!("cannot start the clipboard clearer, so the copy was taken back: {e}"))
    })
}

/// The clearer: wait, then clear the clipboard if it still holds the copy.
fn clear_later(env: &Env) -> Result<u8, Fail> {
    let job = (env.clip.job)()?;
    let (delay, token) = clip::parse_job(&job).ok_or_else(|| Fail::Log("not a clipboard job".into()))?;
    // Short naps against a wall-clock deadline: a nap of the whole delay would not count a suspend.
    let deadline = (env.clip.now)() + delay;
    while let Some(left) = deadline.duration_since((env.clip.now)()).ok().filter(|d| !d.is_zero()) {
        (env.clip.sleep)(left.min(Duration::from_secs(1)));
    }
    (env.clip.clear)(&token)?;
    Ok(0)
}

fn no_home() -> Fail {
    Fail::Log("this user has no home directory in the password database".into())
}

/// The last `n` lines of the audit log (the file is read directly: same user, no agent needed).
fn audit(env: &Env, ai: bool, n: usize, out: &mut dyn Write) -> Result<u8, Fail> {
    let home = doctor::home_of(env).ok_or_else(no_home)?;
    let path = dybw_agent::paths::audit_path(&home);
    let log = match dybw_agent::audit::read(&path, env.uid) {
        Ok(log) => log,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Fail::Log(format!("cannot read the audit log {}: {e}", path.display()))),
    };
    let shown: Vec<_> = log.entries.iter().filter(|e| !ai || e.class == "ai" || e.class == "unknown").collect();
    for e in shown.iter().skip(shown.len().saturating_sub(n)) {
        let who = e.harness.as_deref().or(e.exe.as_deref());
        let cells = [
            Some(e.time.as_str()),
            Some(e.profile.as_str()),
            Some(e.class.as_str()),
            who,
            e.script.as_deref(),
            Some(e.op.as_str()),
            e.kind.as_deref(),
            e.item.as_deref(),
            Some(e.verdict.as_str()),
        ];
        let row: Vec<String> = cells.into_iter().map(|c| escape(c.unwrap_or("-"))).collect();
        writeln!(out, "{}", row.join("\t"))?;
    }
    Ok(0)
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

/// Print the failure as `<who>: <message>`; an ambiguous lookup also lists its candidates as `id<TAB>name<TAB>user`.
fn report(err: &mut dyn Write, who: &str, fail: &Fail) {
    let _ = writeln!(err, "{who}: {fail}");
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
    let profile =
        cli.profile.or_else(|| (env.var)("DYBW_PROFILE").and_then(|v| v.into_string().ok()).filter(|v| !v.is_empty()));
    match execute(cli.command, profile, env, out, err) {
        Ok(code) => code,
        Err(fail) => {
            report(err, "dybw", &fail);
            1
        }
    }
}

/// `run`, or the rbw shim when argv[0] is `rbw` (a symlink to this binary).
pub fn dispatch(args: Vec<std::ffi::OsString>, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let as_rbw = args.first().and_then(|a| std::path::Path::new(a).file_name()).is_some_and(|n| n == "rbw");
    if as_rbw { rbw::run(args, env, out, err) } else { run(args, env, out, err) }
}

pub fn main() -> ExitCode {
    let args = std::env::args_os().collect();
    ExitCode::from(dispatch(args, &Env::real(), &mut std::io::stdout().lock(), &mut std::io::stderr().lock()))
}

#[cfg(test)]
mod rbw_tests;
#[cfg(test)]
mod tests;
