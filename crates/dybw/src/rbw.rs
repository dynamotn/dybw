//! The `rbw` personality: `dybw` invoked as `rbw` parses rbw 1.15's command line and maps each command onto the
//! requests `dybw` sends. The clap model below follows rbw's `src/bin/rbw/main.rs` (rbw 1.15.0, MIT; the licence is in `rbw_completion/LICENSE-rbw`).
//!
//! TODO(Task 4): rbw's output formatting and its own error messages; for now every command prints what `dybw` prints
//! and fails with `rbw <command>: <dybw message>`.

use std::io::Write;

use clap::Parser as _;
use clap::error::ErrorKind;

use crate::rbw_config;
use crate::{Ask, Cmd, Env, Fail, Shape, execute, parse_field, report};
use dybw_proto::Field;

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

/// rbw's `ListField`: `list` and `search` fail on a name it does not know, before anything else.
fn fields(names: &[String], raw: bool) -> Result<Vec<Field>, Fail> {
    if raw {
        return Ok(vec![Field::Id, Field::Name, Field::User, Field::Folder, Field::Type]);
    }
    names.iter().map(|n| parse_field(n).map_err(|_| Fail::Log(format!("unknown field {n}")))).collect()
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

/// Map one `rbw` command onto `dybw`'s, or handle it here.
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
        Opt::Purge => {
            return Err(Fail::Log(
                "dybw has no purge: stop the agent (`rbw stop-agent`) and delete the profile's directory under \
                 ~/.cache/dybw/profiles yourself"
                    .into(),
            ));
        }
        Opt::GenCompletions { shell } => {
            completions(shell, out)?;
            return Ok(0);
        }
        // The API key is the only login there is: `register` and `login` are the same step.
        Opt::Register | Opt::Login => Cmd::Login,
        Opt::Unlock => Cmd::Unlock,
        Opt::Unlocked => Cmd::Unlocked,
        Opt::Sync => Cmd::Sync { all: false },
        Opt::Lock => Cmd::Lock { all: false },
        Opt::StopAgent => Cmd::Agent { command: crate::AgentCmd::Stop },
        Opt::List { fields: names, raw } => {
            Cmd::List { shape: Shape { fields: fields(&names, raw)?, folder: None }, raw }
        }
        // TODO(Task 4): `search --raw` (every field as JSON); `dybw search` has no raw output yet.
        Opt::Search { term, fields: names, folder, raw } => {
            Cmd::Search { term, shape: Shape { fields: fields(&names, raw)?, folder } }
        }
        // rbw's order: --list-fields, --raw, --full, --field, else the password.
        Opt::Get { find_args, field, full, raw, clipboard, list_fields } => {
            let FindArgs { needle, user, folder, ignorecase } = find_args;
            let (field, full, raw) = match (list_fields, raw, full) {
                (true, ..) => (None, false, false),
                (_, true, _) => (None, false, true),
                (_, _, true) => (None, true, false),
                _ => (field, false, false),
            };
            Cmd::Get { item: needle, user, folder, ignorecase, field, full, raw, list_fields, clipboard }
        }
        Opt::Code { find_args: FindArgs { needle, user, folder, ignorecase }, clipboard } => {
            Cmd::Code { item: needle, user, folder, ignorecase, next: false, clipboard }
        }
        // TODO(Task 4): the `$VISUAL`/`$EDITOR` flow; for now the password is typed in the agent's pinentry.
        Opt::Add { name, user, uri, folder } => {
            Cmd::Add { name, user, uri, folder, ask: Ask { notes: false, no_password: false } }
        }
        Opt::Edit { find_args: FindArgs { needle, user, folder, .. } } => {
            Cmd::Edit { item: needle, user, folder, ask: Ask { notes: false, no_password: false } }
        }
        // `ignorecase` is not part of the `dybw` request for these two.
        // TODO(Task 4): case-insensitive `remove` and `history`.
        Opt::Remove { find_args: FindArgs { needle, user, folder, .. } } => Cmd::Remove { item: needle, user, folder },
        Opt::History { find_args: FindArgs { needle, user, folder, .. } } => {
            Cmd::History { item: needle, user, folder }
        }
        // TODO(Task 4): rbw prints the generated password even when it saves it; the agent keeps that one.
        Opt::Generate { len, name, user, uri, folder, no_symbols, only_numbers, nonconfusables, diceware } => {
            let length = u32::try_from(len).map_err(|_| Fail::Log("the length is too large".into()))?;
            Cmd::Generate { length, name, user, uri, folder, no_symbols, only_numbers, nonconfusables, diceware }
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
        Err(fail) => {
            report(err, &format!("rbw {name}"), &fail);
            1
        }
    }
}
