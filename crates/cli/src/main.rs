use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Encoding};
use clap::{Args, Parser, Subcommand, ValueEnum};
use getrandom::SysRng;
use passforme_core::generator::{self, Generated, Language, PassphraseSpec, PasswordSpec};
use passforme_core::item::{Attachment, Field, Item};
use passforme_core::kdf::{KdfParams, SecretKey};
use passforme_core::kind::{Kind, Slot};
use passforme_core::seal::ItemId;
use passforme_core::totp::Totp;
use passforme_core::vault::UnlockedVault;
use rand_core::UnwrapErr;
use secrecy::{ExposeSecret, SecretString};

mod agent;
mod clipboard;
mod config;
mod error;
mod keeper;
mod kinds;
mod prompt;
mod remote;
mod session;
mod store;
mod sync;

use error::Result;
use session::Session;
use store::Store;

/// Minimum master password length, in characters. The Secret Key protects
/// against guessing from stolen server data; this protects a stolen laptop,
/// where the Secret Key file sits next to the vault.
const MIN_MASTER_CHARS: usize = 12;

/// A personal password manager.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the vault and print the Emergency Kit.
    Init,
    /// Generate a password or passphrase and print it.
    Generate {
        #[command(flatten)]
        spec: GenArgs,
        /// Copy to the clipboard instead of printing.
        #[arg(long)]
        copy: bool,
    },
    /// Add an item; asks for its secret (password, API key, token) unless one
    /// is generated. Other kinds (`--kind card`, `pin`, `crypto-seed`…) ask
    /// for each of their fields.
    Add {
        title: String,
        /// What it is: login (default), card, pin, recovery-codes… — see
        /// `passforme kinds`.
        #[arg(long, default_value = "login", value_parser = kind_names())]
        kind: String,
        /// Read the main secret from this file (a private key).
        #[arg(long, value_name = "PATH", conflicts_with = "generate")]
        file: Option<std::path::PathBuf>,
        #[arg(long)]
        username: Option<String>,
        /// Repeat for several addresses.
        #[arg(long)]
        url: Vec<String>,
        /// Generate the password (see the generator options) and copy it.
        #[arg(long)]
        generate: bool,
        #[command(flatten)]
        spec: GenArgs,
        /// Make it readable by programs through the unlock agent.
        #[arg(long)]
        agent: bool,
    },
    /// Add several items in a row, a label and a secret each, unlocking the
    /// vault once; an empty label finishes.
    AddMany,
    /// List the kinds of item and what each holds.
    Kinds,
    /// Print the shell completion script, so Tab completes commands and
    /// options (`source <(passforme completions bash)` in ~/.bashrc).
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Copy the next unused recovery code and mark it used.
    Codes {
        /// Title, or part of it.
        query: String,
        /// Show every code and which are used, instead.
        #[arg(long)]
        list: bool,
    },
    /// List the items.
    List,
    /// Show an item; secrets are masked unless --reveal.
    Show {
        /// Title, or part of it.
        query: String,
        #[arg(long)]
        reveal: bool,
    },
    /// Copy a field of an item to the clipboard, cleared after 30 s.
    Get {
        /// Title, or part of it.
        query: String,
        /// Which field: password (the default: the item's main secret),
        /// username, url, totp, the kind's own (pin, cvv, number, words…)
        /// or any extra field, by name.
        #[arg(long)]
        field: Option<String>,
        /// Print the value alone (no newline) instead: for programs. Served
        /// by the agent without a password; without an agent it asks for the
        /// master password on a terminal and fails at once otherwise.
        #[arg(long)]
        stdout: bool,
        /// Save an attached file instead (`edit --attach`), by its name.
        #[arg(long, value_name = "NAME", conflicts_with_all = ["field", "stdout"])]
        attachment: Option<String>,
        /// Where to save the attachment: a file or a directory; by default
        /// the current directory. An existing file is never overwritten.
        #[arg(long, value_name = "PATH", requires = "attachment")]
        output: Option<std::path::PathBuf>,
    },
    /// Hand the items marked `--agent` to the unlock agent, so programs can
    /// read them with `get --stdout` without the master password.
    Unlock {
        /// Only these items (titles or parts of them; each must be marked
        /// `--agent`). Without any, every marked item, including ones
        /// marked later.
        #[arg(value_name = "ITEM")]
        items: Vec<String>,
        /// How long the agent keeps them: like 30m, 8h, 2d (at most 7d), or
        /// `forever` to keep them until `passforme lock` (or the session ends).
        #[arg(long = "for", value_name = "DURATION", default_value = "8h")]
        duration: String,
    },
    /// Lock now: close the session and empty the unlock agent.
    Lock,
    /// Show the unlock agent and the sync link.
    Status,
    /// Change fields of an item; secrets are prompted for, never passed
    /// as arguments.
    Edit {
        /// Title, or part of it.
        query: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        username: Option<String>,
        /// Add an address (repeatable).
        #[arg(long)]
        url: Vec<String>,
        /// Remove an address (repeatable).
        #[arg(long)]
        rm_url: Vec<String>,
        /// Type a new secret (password, API key, token).
        #[arg(long, conflicts_with = "generate")]
        password: bool,
        /// Generate a new password (see the generator options) and copy it.
        #[arg(long)]
        generate: bool,
        #[command(flatten)]
        spec: GenArgs,
        /// Type new notes (several lines; empty removes them).
        #[arg(long)]
        notes: bool,
        /// Paste the TOTP secret or otpauth:// URI (empty removes it).
        #[arg(long)]
        totp: bool,
        /// Set a visible extra field, typed at a prompt.
        #[arg(long = "set-field", value_name = "NAME")]
        field: Vec<String>,
        /// Set a concealed extra field (like a PIN), typed without echo.
        #[arg(long = "set-secret-field", value_name = "NAME")]
        secret_field: Vec<String>,
        /// Remove an extra field.
        #[arg(long, value_name = "NAME")]
        rm_field: Vec<String>,
        /// Make it readable by programs through the unlock agent.
        #[arg(long, conflicts_with = "no_agent")]
        agent: bool,
        /// Stop handing it to the unlock agent.
        #[arg(long)]
        no_agent: bool,
        /// Replace the recovery codes (pasted, one per line).
        #[arg(long)]
        codes: bool,
        /// Keep a small file inside the item (repeatable; at most 512 KiB in
        /// all); one with the same name is replaced.
        #[arg(long, value_name = "PATH")]
        attach: Vec<std::path::PathBuf>,
        /// Remove an attached file, by its name.
        #[arg(long, value_name = "NAME")]
        rm_attachment: Vec<String>,
        /// Change what the item is (`passforme kinds`); its fields stay.
        #[arg(long, value_parser = kind_names())]
        kind: Option<String>,
    },
    /// Print the current TOTP code of an item.
    Totp {
        /// Title, or part of it.
        query: String,
    },
    /// Change the master password (and rotate the vault key).
    Passwd,
    /// Put this vault on an empty sync server and link it.
    Register {
        /// The server's address, like `https://pfm.example.com`.
        url: String,
    },
    /// Set up this device from a sync server.
    Login {
        /// The server's address, like `https://pfm.example.com`.
        url: String,
    },
    /// Exchange changes with the sync server.
    Sync,
    /// Delete an item.
    Rm {
        /// Title, or part of it.
        query: String,
    },
    /// Internal: the unlock agent (spawned by `unlock`).
    #[command(name = "__agent", hide = true)]
    Agent { secs: u64 },
    /// Internal: the session keeper (spawned after the master password is
    /// typed at a terminal).
    #[command(name = "__session", hide = true)]
    Session { idle_secs: u64 },
    /// Internal: clear the clipboard later (spawned by `get`).
    #[command(name = "__clear-clipboard", hide = true)]
    ClearClipboard { after_secs: u64 },
}

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // one switch per character class, as on the command line
struct GenArgs {
    /// Password length [default: 29].
    // An Option, not a clap default, so `add --length 29` without
    // `--generate` is seen as given and refused.
    #[arg(long, conflicts_with = "words")]
    length: Option<usize>,
    #[arg(long, conflicts_with = "words")]
    no_lowercase: bool,
    #[arg(long, conflicts_with = "words")]
    no_uppercase: bool,
    #[arg(long, conflicts_with = "words")]
    no_digits: bool,
    /// Add symbols (!#$%…), for sites that demand one; off by default.
    #[arg(long, conflicts_with = "words")]
    symbols: bool,
    /// Leave out characters easily confused, like l, 1, O and 0.
    #[arg(long, conflicts_with = "words")]
    avoid_ambiguous: bool,
    /// A passphrase of this many words instead of random characters.
    #[arg(long)]
    words: Option<usize>,
    /// Between passphrase words [default: -].
    #[arg(long, requires = "words")]
    separator: Option<String>,
    /// Language of the passphrase words; by default the system's (`LANG`),
    /// Portuguese when it starts with `pt`, English otherwise.
    #[arg(long, value_enum, requires = "words")]
    lang: Option<LangArg>,
}

#[derive(Clone, Copy, ValueEnum)]
enum LangArg {
    En,
    #[value(name = "pt-br")]
    PtBr,
}

impl LangArg {
    /// The first of `LC_ALL`, `LC_MESSAGES`, `LANG` that is set, as gettext
    /// does; `pt_BR.UTF-8`, `pt_PT` and `pt` all mean Portuguese.
    fn from_env() -> Self {
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .unwrap_or_default();
        if locale.starts_with("pt") {
            Self::PtBr
        } else {
            Self::En
        }
    }
}

impl GenArgs {
    /// Generator options mean nothing without `--generate` in `add` and
    /// `edit`; refused rather than silently ignored.
    fn only_with_generate(&self, generate: bool) -> Result<()> {
        let given = self.length.is_some()
            || self.no_lowercase
            || self.no_uppercase
            || self.no_digits
            || self.symbols
            || self.avoid_ambiguous
            || self.words.is_some()
            || self.separator.is_some()
            || self.lang.is_some();
        if given && !generate {
            return Err(
                "the generator options (--symbols, --length, --words…) need --generate".into(),
            );
        }
        Ok(())
    }

    fn generate(&self) -> Result<Generated> {
        let mut rng = UnwrapErr(SysRng);
        Ok(match self.words {
            Some(words) => generator::generate_passphrase(
                &PassphraseSpec {
                    words,
                    separator: self.separator.clone().unwrap_or_else(|| "-".to_owned()),
                    language: match self.lang.unwrap_or_else(LangArg::from_env) {
                        LangArg::En => Language::English,
                        LangArg::PtBr => Language::PortugueseBr,
                    },
                },
                &mut rng,
            )?,
            None => generator::generate_password(
                &PasswordSpec {
                    length: self.length.unwrap_or(PasswordSpec::default().length),
                    lowercase: !self.no_lowercase,
                    uppercase: !self.no_uppercase,
                    digits: !self.no_digits,
                    symbols: self.symbols,
                    avoid_ambiguous: self.avoid_ambiguous,
                },
                &mut rng,
            )?,
        })
    }
}

fn main() -> ExitCode {
    harden();
    if let Some(hint) = retired_option() {
        eprintln!("passforme: {hint}");
        return ExitCode::from(2);
    }
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("passforme: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Short options were dropped on 2026-10-21: every option is long only, so
/// commands read the same everywhere. One typed from habit gets its new
/// name rather than a bare "unexpected argument".
const RETIRED: &[(&str, &str)] = &[
    ("-u", "--username"),
    ("-g", "--generate"),
    ("-k", "--kind"),
    ("-s", "--symbols"),
    ("-l", "--length"),
    ("-w", "--words"),
    ("-f", "--field"),
];

fn retired_option() -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).take_while(|a| a != "--").collect();
    for arg in &args {
        if let Some((short, long)) = RETIRED.iter().find(|(short, _)| arg == short) {
            return Some(format!("{short} is now {long} (options are long only)"));
        }
    }
    let in_edit = args.first().is_some_and(|c| c == "edit");
    for (old, new) in [
        ("--field", "--set-field"),
        ("--secret-field", "--set-secret-field"),
    ] {
        if in_edit
            && args
                .iter()
                .any(|a| a == old || a.starts_with(&format!("{old}=")))
        {
            return Some(format!("in `edit`, {old} is now {new}"));
        }
    }
    None
}

/// The kinds as the parser's possible values: Tab completes them, and a
/// wrong one is answered with the list.
fn kind_names() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(Kind::ALL.map(Kind::name))
}

/// The script for both names, `passforme` and its `pfm` link, where the
/// shell's format allows two in one file. The internal commands (`__agent`,
/// `__session`, `__clear-clipboard`) are hidden from help but `clap_complete`
/// still offers them, so they are taken out of the bash and fish word lists.
fn completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::Shell;
    let names: &[&str] = match shell {
        Shell::Bash | Shell::Fish => &["passforme", "pfm"],
        _ => &["passforme"],
    };
    let mut script = Vec::new();
    for name in names {
        clap_complete::generate(shell, &mut Cli::command(), *name, &mut script);
    }
    let script = String::from_utf8(script).expect("clap_complete writes UTF-8");
    for line in script.lines() {
        if line.trim_start().starts_with("opts=\"") {
            let words: Vec<&str> = line.split(' ').filter(|w| !w.starts_with("__")).collect();
            println!("{}", words.join(" "));
        } else if !(shell == Shell::Fish && line.contains("-a \"__")) {
            println!("{line}");
        }
    }
}

/// No core dumps (they would write the decrypted vault to disk), and not
/// dumpable, which also stops other processes of the same user from
/// attaching with ptrace or reading `/proc/<pid>/mem`.
fn harden() {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    let no_core = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if setrlimit(Resource::Core, no_core).is_err()
        || set_dumpable_behavior(DumpableBehavior::NotDumpable).is_err()
    {
        eprintln!("passforme: warning: could not disable core dumps");
    }
}

#[allow(clippy::too_many_lines)] // one arm per command, nothing else
fn run(command: Command) -> Result<()> {
    match command {
        Command::Init => init(),
        Command::Generate { spec, copy } => generate(&spec, copy),
        Command::Add {
            title,
            kind,
            file,
            username,
            url,
            generate,
            spec,
            agent,
        } => {
            spec.only_with_generate(generate)?;
            add(
                title,
                kinds::parse(&kind)?,
                kinds::Given {
                    username,
                    urls: url,
                    generate: generate.then_some(&spec),
                    file: file.as_deref(),
                },
                agent,
            )
        }
        Command::AddMany => add_many(),
        Command::Kinds => {
            kinds::print_all();
            Ok(())
        }
        Command::Completions { shell } => {
            completions(shell);
            Ok(())
        }
        Command::Codes { query, list } => codes(&query, list),
        Command::List => list(),
        Command::Show { query, reveal } => show(&query, reveal),
        Command::Get {
            query,
            field,
            stdout,
            attachment,
            output,
        } => {
            if let Some(name) = attachment {
                save_attachment(&query, &name, output.as_deref())
            } else if stdout {
                get_stdout(&query, field.as_deref())
            } else {
                get(&query, field.as_deref())
            }
        }
        Command::Unlock { duration, items } => unlock_agent(&duration, &items),
        Command::Lock => lock(),
        Command::Status => status(),
        Command::Agent { secs } => agent::serve(secs),
        Command::Session { idle_secs } => keeper::serve(idle_secs),
        Command::Edit {
            query,
            title,
            username,
            url,
            rm_url,
            password,
            generate,
            spec,
            notes,
            totp,
            field,
            secret_field,
            rm_field,
            agent,
            no_agent,
            codes,
            attach,
            rm_attachment,
            kind,
        } => {
            spec.only_with_generate(generate)?;
            edit(
                &query,
                &Edit {
                    title,
                    username,
                    add_urls: url,
                    rm_urls: rm_url,
                    password: if generate {
                        NewPassword::Generate(spec)
                    } else if password {
                        NewPassword::Prompt
                    } else {
                        NewPassword::Keep
                    },
                    notes,
                    totp,
                    fields: field,
                    secret_fields: secret_field,
                    rm_fields: rm_field,
                    agent: if agent {
                        Some(true)
                    } else if no_agent {
                        Some(false)
                    } else {
                        None
                    },
                    codes,
                    attach,
                    rm_attachments: rm_attachment,
                    kind: kind.as_deref().map(kinds::parse).transpose()?,
                },
            )
        }
        Command::Totp { query } => totp(&query),
        Command::Passwd => passwd(),
        Command::Register { url } => sync::register(&url),
        Command::Login { url } => sync::login(&url),
        Command::Sync => {
            let mut session = Session::open()?;
            sync::sync(&mut session)?.print();
            Ok(())
        }
        Command::Rm { query } => remove(&query),
        Command::ClearClipboard { after_secs } => clipboard::clear_later(after_secs),
    }
}

fn generate(spec: &GenArgs, copy: bool) -> Result<()> {
    let generated = spec.generate()?;
    if copy {
        clipboard::copy_and_clear_later(generated.secret.expose_secret().as_bytes())?;
        eprintln!(
            "Copied ({:.0} bits); cleared in {} s.",
            generated.entropy_bits,
            clipboard::CLEAR_AFTER_SECS
        );
    } else {
        println!("{}", generated.secret.expose_secret());
        eprintln!("{:.0} bits", generated.entropy_bits);
    }
    Ok(())
}

fn lock() -> Result<()> {
    let session = keeper::lock()?;
    let agent = agent::request(&agent::Request::Lock)?.is_some();
    eprintln!(
        "{}",
        match (session, agent) {
            (true, true) => "Session closed and agent emptied.",
            (true, false) => "Session closed.",
            (false, true) => "Agent emptied.",
            (false, false) => "Nothing was unlocked.",
        }
    );
    Ok(())
}

fn status() -> Result<()> {
    match agent::request(&agent::Request::Status)? {
        Some(response) => {
            let time = match response.expires {
                Some(at) => format!("{} min left", at.saturating_sub(now()).div_ceil(60)),
                None => "no time limit".to_owned(),
            };
            let scope = if response.selection.is_some() {
                "chosen items"
            } else {
                "every marked item"
            };
            match response.titles {
                Some(titles) => {
                    println!("Agent:  unlocked, {time}, {scope}: {}", titles.join(", "));
                }
                None => println!(
                    "Agent:  unlocked, {time}, {} item(s)",
                    response.items.unwrap_or(0)
                ),
            }
        }
        None => println!("Agent:  locked"),
    }
    match keeper::status()? {
        Some((expires, idle)) => println!(
            "Session: open, locks in {} unless used (after {} idle)",
            human_secs(expires.saturating_sub(now())),
            human_secs(idle)
        ),
        None => println!("Session: closed (the next command asks for the master password)"),
    }
    let store = Store::locate()?;
    match store.sync_state()? {
        Some(state) => println!("Sync:   {} (revision {})", state.url, state.revision),
        None => println!("Sync:   not linked (only on this device; see `passforme register`)"),
    }
    println!("Vault:  {}", store.vault_path().display());
    Ok(())
}

fn init() -> Result<()> {
    let store = Store::locate()?;
    if store.exists() {
        return Err(format!("a vault already exists at {}", store.vault_path().display()).into());
    }
    let password = new_master_password()?;

    let mut rng = UnwrapErr(SysRng);
    let secret_key = SecretKey::generate(&mut rng);
    eprintln!("Deriving keys...");
    let vault = UnlockedVault::create(&password, &secret_key, &KdfParams::DEFAULT, &mut rng)?;
    store.create_secret_key(&secret_key)?;
    store.save_vault(vault.file())?;

    println!(
        "\nVault created at {}.\n\n\
         EMERGENCY KIT: write this down or print it, and keep it offline.\n\
         Opening the vault on a new device needs this Secret Key AND the master\n\
         password. Lose either one and nobody, not even you, can open the vault.\n\n\
         \x20   Secret Key: {}\n\n\
         This device keeps a copy next to the vault; the master password is\n\
         stored nowhere.",
        store.vault_path().display(),
        *secret_key.to_kit()
    );
    Ok(())
}

/// Asks for a new master password twice and checks its length.
fn new_master_password() -> Result<SecretString> {
    eprintln!(
        "Choose a master password of at least {MIN_MASTER_CHARS} characters. It cannot be \
         recovered;\n`passforme generate --words 6` makes a good one to memorize."
    );
    let password = prompt::secret("New master password: ")?;
    if password.expose_secret().chars().count() < MIN_MASTER_CHARS {
        return Err(
            format!("the master password needs at least {MIN_MASTER_CHARS} characters").into(),
        );
    }
    let again = prompt::secret("Repeat it: ")?;
    if again.expose_secret() != password.expose_secret() {
        return Err("the passwords do not match".into());
    }
    Ok(password)
}

/// For commands that only read.
fn unlock() -> Result<UnlockedVault> {
    Ok(Session::open()?.vault)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn add(title: String, kind: Kind, given: kinds::Given<'_>, agent: bool) -> Result<()> {
    kinds::check_given(kind, &given)?;
    let mut session = Session::open()?;
    let vault = &mut session.vault;
    if vault
        .items()?
        .iter()
        .any(|(_, item)| item.title.eq_ignore_ascii_case(&title))
    {
        return Err(format!("an item called '{title}' already exists").into());
    }

    let mut item = Item::default();
    item.title = title;
    item.kind = kind;
    let generated = if kind == Kind::Login && given.file.is_none() {
        fill_login(&mut item, given)?
    } else {
        kinds::fill(&mut item, given)?
    };
    item.agent = agent;
    item.created = now();
    item.modified = item.created;
    vault.add(&item, &mut UnwrapErr(SysRng))?;
    eprintln!("Added '{}'.", item.title);
    session.commit()?;
    if let Some(g) = generated {
        clipboard::copy_and_clear_later(g.secret.expose_secret().as_bytes())?;
        eprintln!(
            "Generated password ({:.0} bits) copied; cleared in {} s.",
            g.entropy_bits,
            clipboard::CLEAR_AFTER_SECS
        );
    }
    Ok(())
}

/// A login as it always was: the secret asked twice (it is typed), the
/// username and URLs only from the command line.
fn fill_login(item: &mut Item, given: kinds::Given<'_>) -> Result<Option<Generated>> {
    let generated = given.generate.map(GenArgs::generate).transpose()?;
    let password = if let Some(g) = &generated {
        g.secret.clone()
    } else {
        let first =
            prompt::secret("Secret for the item (password, API key, token; empty for none): ")?;
        if !first.expose_secret().is_empty() {
            let again = prompt::secret("Repeat the secret: ")?;
            if again.expose_secret() != first.expose_secret() {
                return Err("the passwords do not match".into());
            }
        }
        first
    };
    item.username = given.username.unwrap_or_default();
    password.expose_secret().clone_into(&mut item.password);
    item.urls = given.urls;
    Ok(generated)
}

/// For moving many passwords in by hand: the secret is asked once (no
/// repeat), since it is pasted rather than typed. The vault is saved after
/// every item, so stopping halfway loses nothing; the sync runs once at the
/// end.
fn add_many() -> Result<()> {
    let mut session = Session::open()?;
    eprintln!("A label and its secret per item; an empty label finishes.");
    let mut added = 0usize;
    loop {
        let label = prompt::line("Label: ")?;
        let label = label.trim();
        if label.is_empty() {
            break;
        }
        if session
            .vault
            .items()?
            .iter()
            .any(|(_, item)| item.title.eq_ignore_ascii_case(label))
        {
            eprintln!("'{label}' already exists; skipped.");
            continue;
        }
        let secret = prompt::secret("Secret: ")?;
        if secret.expose_secret().is_empty() {
            eprintln!("Empty secret; '{label}' skipped.");
            continue;
        }
        let mut item = Item::default();
        label.clone_into(&mut item.title);
        secret.expose_secret().clone_into(&mut item.password);
        item.created = now();
        item.modified = item.created;
        session.vault.add(&item, &mut UnwrapErr(SysRng))?;
        session.store.save_vault(session.vault.file())?;
        added += 1;
        eprintln!("Added '{label}'.");
    }
    eprintln!("{added} item(s) added.");
    if added > 0 {
        session.commit()?;
    }
    Ok(())
}

/// Every item with what it holds — never the secrets themselves.
fn list() -> Result<()> {
    let vault = unlock()?;
    let mut items = vault.items()?;
    items.sort_by_key(|(_, item)| item.title.to_lowercase());
    if items.is_empty() {
        eprintln!("The vault is empty; add an item with `passforme add`.");
        return Ok(());
    }
    let rows: Vec<[String; 6]> = items
        .iter()
        .map(|(_, item)| {
            let mut also = Vec::new();
            if item.password.is_empty() && item.kind.password_label().is_some() {
                also.push("no secret".to_owned());
            }
            if item.urls.len() > 1 {
                also.push(format!("+{} URL", item.urls.len() - 1));
            }
            if !item.totp.is_empty() {
                also.push("TOTP".to_owned());
            }
            if !item.notes.is_empty() {
                also.push("notes".to_owned());
            }
            if !item.fields.is_empty() {
                also.push(format!("{} field(s)", item.fields.len()));
            }
            if !item.codes.is_empty() {
                let left = item.codes.iter().filter(|c| !c.used).count();
                also.push(format!("{left}/{} codes", item.codes.len()));
            }
            if !item.attachments.is_empty() {
                also.push(format!("{} file(s)", item.attachments.len()));
            }
            [
                item.title.clone(),
                item.kind.name().to_owned(),
                item.username.clone(),
                item.urls.first().cloned().unwrap_or_default(),
                if item.agent { "yes" } else { "" }.to_owned(),
                also.join(", "),
            ]
        })
        .collect();
    let header = ["TITLE", "KIND", "USERNAME", "URL", "AGENT", "ALSO"].map(str::to_owned);
    let widths: Vec<usize> = (0..6)
        .map(|c| {
            std::iter::once(&header)
                .chain(&rows)
                .map(|r| r[c].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in std::iter::once(&header).chain(&rows) {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, &w)| format!("{cell:w$}"))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
    let marked = items.iter().filter(|(_, i)| i.agent).count();
    eprintln!(
        "{} item(s); {marked} marked for the agent (`passforme unlock`).",
        items.len()
    );
    Ok(())
}

/// Which of `titles` `query` means: an exact (case-insensitive) title wins,
/// otherwise the only title containing it. Shared with the agent, so both
/// resolve a query the same way.
fn pick_index(titles: &[&str], query: &str) -> Result<usize> {
    let needle = query.to_lowercase();
    if let Some(index) = titles.iter().position(|t| t.to_lowercase() == needle) {
        return Ok(index);
    }
    let matches: Vec<usize> = (0..titles.len())
        .filter(|&i| titles[i].to_lowercase().contains(&needle))
        .collect();
    match matches[..] {
        [] => Err(format!("no item matches '{query}'").into()),
        [index] => Ok(index),
        _ => {
            let names: Vec<&str> = matches.iter().map(|&i| titles[i]).collect();
            Err(format!("'{query}' matches several items: {}", names.join(", ")).into())
        }
    }
}

fn find(vault: &UnlockedVault, query: &str) -> Result<(ItemId, Item)> {
    let mut items = vault.items()?;
    let titles: Vec<&str> = items.iter().map(|(_, i)| i.title.as_str()).collect();
    let index = pick_index(&titles, query)?;
    Ok(items.swap_remove(index))
}

fn show(query: &str, reveal: bool) -> Result<()> {
    let vault = unlock()?;
    let (_, item) = find(&vault, query)?;
    let kind = item.kind;
    let mask = |value: &str, concealed: bool| {
        if concealed && !reveal {
            "********".to_owned()
        } else {
            value.to_owned()
        }
    };
    let mut rows: Vec<(String, String)> = vec![("Title".into(), item.title.clone())];
    if kind != Kind::Login {
        rows.push(("Kind".into(), kind.name().into()));
    }
    // In the order the kind asks for them; then whatever else it holds
    // (a field added with `edit`, a slot of another kind after `--kind`).
    let mut shown_fields = Vec::new();
    let mut username_shown = false;
    let mut password_shown = false;
    let mut urls_shown = false;
    for slot in kind.slots() {
        match *slot {
            Slot::Username(label) if !item.username.is_empty() => {
                rows.push((label.into(), item.username.clone()));
                username_shown = true;
            }
            Slot::Password(label) if !item.password.is_empty() => {
                rows.push((label.into(), mask(&item.password, true)));
                password_shown = true;
            }
            Slot::Urls => {
                rows.extend(item.urls.iter().map(|u| ("URL".into(), u.clone())));
                urls_shown = true;
            }
            Slot::Field { name, .. } => {
                if let Some(f) = item.fields.iter().find(|f| f.name == name) {
                    rows.push((f.name.clone(), mask(&f.value, f.concealed)));
                    shown_fields.push(name);
                }
            }
            _ => {}
        }
    }
    if !username_shown && !item.username.is_empty() {
        rows.push(("Username".into(), item.username.clone()));
    }
    if !password_shown && !item.password.is_empty() {
        rows.push(("Password".into(), mask(&item.password, true)));
    }
    if !urls_shown {
        rows.extend(item.urls.iter().map(|u| ("URL".into(), u.clone())));
    }
    if !item.totp.is_empty() {
        let line = match Totp::parse(&item.totp) {
            Ok(totp) => {
                let now = now();
                format!("{}  (valid {} s)", *totp.code_at(now), totp.remaining(now))
            }
            Err(e) => format!("unusable: {e}"),
        };
        rows.push(("TOTP".into(), line));
        if reveal {
            rows.push(("TOTP key".into(), item.totp.clone()));
        }
    }
    for field in item
        .fields
        .iter()
        .filter(|f| !shown_fields.contains(&f.name.as_str()))
    {
        rows.push((field.name.clone(), mask(&field.value, field.concealed)));
    }
    if !item.codes.is_empty() {
        let left = item.codes.iter().filter(|c| !c.used).count();
        rows.push((
            "Codes".into(),
            format!("{left} of {} unused (`passforme codes`)", item.codes.len()),
        ));
    }
    for attachment in &item.attachments {
        rows.push((
            "Attachment".into(),
            format!(
                "{} ({})",
                attachment.name,
                human_bytes(attachment_len(attachment))
            ),
        ));
    }
    if item.agent {
        rows.push((
            "Agent".into(),
            "readable by programs while `passforme unlock` is active".into(),
        ));
    }
    print_rows(&rows);
    if !item.notes.is_empty() {
        println!("Notes:\n{}", item.notes);
    }
    Ok(())
}

/// Labels padded to a common width; a multi-line value (a private key)
/// starts on its own line.
fn print_rows(rows: &[(String, String)]) {
    let width = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0)
        + 1;
    for (label, value) in rows {
        let label = format!("{label}:");
        if value.contains('\n') {
            println!("{label}\n{}", value.trim_end());
        } else {
            println!("{label:width$} {value}");
        }
    }
}

/// Copies the next unused recovery code and marks it used, or lists them.
fn codes(query: &str, list: bool) -> Result<()> {
    let mut session = Session::open()?;
    let (id, mut item) = find(&session.vault, query)?;
    if item.codes.is_empty() {
        return Err(format!(
            "'{}' has no recovery codes; add them with `passforme edit '{}' --codes`",
            item.title, item.title
        )
        .into());
    }
    let total = item.codes.len();
    if list {
        for (n, code) in item.codes.iter().enumerate() {
            let used = if code.used { "  (used)" } else { "" };
            println!("{:>2}. {}{used}", n + 1, code.code);
        }
        return Ok(());
    }
    let Some(n) = item.codes.iter().position(|c| !c.used) else {
        return Err(format!(
            "all {total} codes of '{}' are used: make new ones on the site, then \
             `passforme edit '{}' --codes`",
            item.title, item.title
        )
        .into());
    };
    // Copied before saving: if the clipboard fails, the code stays unused.
    clipboard::copy_and_clear_later(item.codes[n].code.as_bytes())?;
    item.codes[n].used = true;
    item.modified = now();
    session.vault.update(&id, &item, &mut UnwrapErr(SysRng))?;
    let left = item.codes.iter().filter(|c| !c.used).count();
    eprintln!(
        "Copied code {} of {total} from '{}', now marked used; {left} left. Cleared in {} s.",
        n + 1,
        item.title,
        clipboard::CLEAR_AFTER_SECS
    );
    match left {
        0 => eprintln!("That was the last one: make new codes on the site."),
        1 | 2 => eprintln!("Few codes left: make new ones on the site soon."),
        _ => {}
    }
    session.commit()
}

/// A field's name (for messages) and value; the TOTP field is the current
/// code. Shared with the agent.
fn field_value(item: &Item, field: Option<&str>) -> Result<(String, zeroize::Zeroizing<String>)> {
    kinds::lookup(item, field)
}

fn get(query: &str, field: Option<&str>) -> Result<()> {
    let vault = unlock()?;
    let (_, item) = find(&vault, query)?;
    let (name, value) = field_value(&item, field)?;
    clipboard::copy_and_clear_later(value.as_bytes())?;
    eprintln!(
        "Copied the {name} of '{}'; cleared in {} s.",
        item.title,
        clipboard::CLEAR_AFTER_SECS
    );
    Ok(())
}

/// `get --stdout`: the agent first; without one, the master password on a
/// terminal, and an immediate failure anywhere else (a program must never be
/// left waiting on a prompt it cannot answer).
fn get_stdout(query: &str, field: Option<&str>) -> Result<()> {
    use std::io::{IsTerminal, Write};
    // "password" when none was asked: what agents started by older
    // binaries expect, and the main secret of every kind that has one.
    let field_name = field.unwrap_or("password").to_owned();
    let request = agent::Request::Get {
        query: query.to_owned(),
        field: field_name,
    };
    let value = match agent::request(&request)? {
        Some(agent::Response {
            ok: true,
            value: Some(value),
            ..
        }) => zeroize::Zeroizing::new(value),
        Some(response) if !std::io::stdin().is_terminal() => {
            return Err(response
                .error
                .unwrap_or_else(|| "the agent refused".into())
                .into());
        }
        None if !std::io::stdin().is_terminal() => {
            return Err("the vault is locked: run `passforme unlock` in a terminal".into());
        }
        _ => {
            let vault = unlock()?;
            let (_, item) = find(&vault, query)?;
            field_value(&item, field)?.1
        }
    };
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes())?;
    out.flush()?;
    Ok(())
}

/// `--for` in seconds: `30m`, `8h`, `2d`, plain seconds, or `forever`
/// (`None`, no limit).
/// "45 s", "15 min", "2 h 5 min".
fn human_secs(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs.div_ceil(60)),
        _ => match (secs / 3600, (secs % 3600) / 60) {
            (h, 0) => format!("{h} h"),
            (h, m) => format!("{h} h {m} min"),
        },
    }
}

fn parse_duration(text: &str) -> Result<Option<u64>> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("forever") {
        return Ok(None);
    }
    let (number, unit) = match text.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&text[..i], c),
        _ => (text, 's'),
    };
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return Err(format!("'{text}': use s, m, h, d or forever").into()),
    };
    let secs = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|&s| (1..=agent::MAX_SECS).contains(&s))
        .ok_or_else(|| format!("'{text}' is not a duration between 1s and 7d (or forever)"))?;
    Ok(Some(secs))
}

fn unlock_agent(duration: &str, names: &[String]) -> Result<()> {
    let secs = parse_duration(duration)?;
    let mut session = Session::open()?;
    if session.store.sync_state()?.is_some() {
        match sync::sync(&mut session) {
            Ok(summary) => summary.print(),
            Err(e) => eprintln!("Sync failed ({e}); using this device's copy."),
        }
    }
    let selection = if names.is_empty() {
        None
    } else {
        let all = session.vault.items()?;
        let titles: Vec<&str> = all.iter().map(|(_, i)| i.title.as_str()).collect();
        let mut ids = Vec::new();
        for name in names {
            let (id, item) = &all[pick_index(&titles, name)?];
            if !item.agent {
                return Err(format!(
                    "'{}' is not marked for the agent; mark it first with \
                     `passforme edit '{}' --agent`",
                    item.title, item.title
                )
                .into());
            }
            let id = Base64::encode_string(id.as_bytes());
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        Some(ids)
    };
    let items = agent_items(&session.vault, selection.as_deref())?;
    if items.is_empty() {
        return Err(
            "no item is marked for the agent; mark one with `passforme edit ITEM --agent`".into(),
        );
    }
    let titles: Vec<String> = items.iter().map(|i| i.title.clone()).collect();
    agent::start(&agent::Load { selection, items }, secs)?;
    let how_long = if secs.is_some() {
        format!("for {duration}")
    } else {
        "with no time limit (until a reboot or logout)".to_owned()
    };
    eprintln!(
        "The agent holds {} item(s) {how_long}: {}. `passforme lock` empties it.",
        titles.len(),
        titles.join(", ")
    );
    Ok(())
}

/// The marked items, limited to `selection` (base64 ids) when given.
fn agent_items(vault: &UnlockedVault, selection: Option<&[String]>) -> Result<Vec<Item>> {
    Ok(vault
        .items()?
        .into_iter()
        .filter(|(id, item)| {
            item.agent
                && selection.is_none_or(|ids| ids.contains(&Base64::encode_string(id.as_bytes())))
        })
        // Programs read values, not files: attachments stay out of the agent.
        .map(|(_, mut item)| {
            item.attachments.clear();
            item
        })
        .collect())
}

/// After a change, rebuilds a running agent from the vault with the same
/// selection and the time it had left. Only a command that has just opened
/// the vault with the master password does this; the agent itself takes no
/// new values from anyone. Returns what to tell the user.
fn refresh_agent(vault: &UnlockedVault) -> Result<Option<String>> {
    let Some(status) = agent::request(&agent::Request::Status)? else {
        return Ok(None);
    };
    let secs = match status.expires {
        Some(at) if at <= now() => return Ok(None),
        Some(at) => Some(at - now()),
        None => None,
    };
    let items = agent_items(vault, status.selection.as_deref())?;
    if items.is_empty() {
        agent::request(&agent::Request::Lock)?;
        return Ok(Some(
            "The agent had no marked item left and was emptied.".into(),
        ));
    }
    let titles: Vec<String> = items.iter().map(|i| i.title.clone()).collect();
    agent::start(
        &agent::Load {
            selection: status.selection,
            items,
        },
        secs,
    )?;
    Ok(Some(format!("Agent refreshed: {}.", titles.join(", "))))
}

fn remove(query: &str) -> Result<()> {
    let mut session = Session::open()?;
    let vault = &mut session.vault;
    let (id, item) = find(vault, query)?;
    let answer = prompt::line(&format!(
        "This deletes '{}' for good. Type the title to confirm: ",
        item.title
    ))?;
    if answer != item.title {
        return Err("not confirmed; nothing deleted".into());
    }
    vault.remove(&id)?;
    eprintln!("Deleted '{}'.", item.title);
    session.commit()?;
    Ok(())
}

enum NewPassword {
    Keep,
    Prompt,
    Generate(GenArgs),
}

struct Edit {
    title: Option<String>,
    username: Option<String>,
    add_urls: Vec<String>,
    rm_urls: Vec<String>,
    password: NewPassword,
    notes: bool,
    totp: bool,
    fields: Vec<String>,
    secret_fields: Vec<String>,
    rm_fields: Vec<String>,
    agent: Option<bool>,
    codes: bool,
    attach: Vec<std::path::PathBuf>,
    rm_attachments: Vec<String>,
    kind: Option<Kind>,
}

impl Edit {
    fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.username.is_none()
            && self.add_urls.is_empty()
            && self.rm_urls.is_empty()
            && matches!(self.password, NewPassword::Keep)
            && !self.notes
            && !self.totp
            && self.fields.is_empty()
            && self.secret_fields.is_empty()
            && self.rm_fields.is_empty()
            && self.agent.is_none()
            && !self.codes
            && self.attach.is_empty()
            && self.rm_attachments.is_empty()
            && self.kind.is_none()
    }
}

fn edit(query: &str, change: &Edit) -> Result<()> {
    if change.is_empty() {
        return Err("nothing to change; see `passforme edit --help`".into());
    }
    let mut session = Session::open()?;
    let vault = &mut session.vault;
    let (id, mut item) = find(vault, query)?;

    if let Some(title) = &change.title {
        let taken = vault
            .items()?
            .iter()
            .any(|(other, i)| *other != id && i.title.eq_ignore_ascii_case(title));
        if taken {
            return Err(format!("an item called '{title}' already exists").into());
        }
        item.title.clone_from(title);
    }
    if let Some(username) = &change.username {
        item.username.clone_from(username);
    }
    for url in &change.rm_urls {
        let before = item.urls.len();
        item.urls.retain(|u| u != url);
        if item.urls.len() == before {
            return Err(format!("'{}' has no URL {url}", item.title).into());
        }
    }
    for url in &change.add_urls {
        if !item.urls.contains(url) {
            item.urls.push(url.clone());
        }
    }
    let mut generated = None;
    match &change.password {
        NewPassword::Keep => {}
        NewPassword::Prompt => {
            let password = prompt::secret("New secret for the item (password, API key, token): ")?;
            let again = prompt::secret("Repeat the secret: ")?;
            if again.expose_secret() != password.expose_secret() {
                return Err("the passwords do not match".into());
            }
            password.expose_secret().clone_into(&mut item.password);
        }
        NewPassword::Generate(spec) => {
            if !kinds::generates(item.kind) {
                return Err(format!(
                    "{} items have no password to generate; use --password to type the secret",
                    item.kind.name()
                )
                .into());
            }
            let g = spec.generate()?;
            g.secret.expose_secret().clone_into(&mut item.password);
            generated = Some(g);
        }
    }
    if change.totp {
        let text = prompt::secret("TOTP secret or otpauth:// URI (empty removes it): ")?;
        if !text.expose_secret().trim().is_empty() {
            Totp::parse(text.expose_secret()).map_err(|e| e.to_string())?;
        }
        text.expose_secret().trim().clone_into(&mut item.totp);
    }
    apply_fields(&mut item, change)?;
    apply_attachments(&mut item, change)?;
    if let Some(agent) = change.agent {
        item.agent = agent;
    }
    if let Some(kind) = change.kind {
        item.kind = kind;
    }
    if change.codes {
        item.codes = kinds::read_codes()?;
    }
    // Last: it reads up to the end of input.
    if change.notes {
        prompt::multiline("Notes (finish with Ctrl-D on an empty line):")?
            .trim_end()
            .clone_into(&mut item.notes);
    }

    item.modified = now();
    vault.update(&id, &item, &mut UnwrapErr(SysRng))?;
    eprintln!("Updated '{}'.", item.title);
    session.commit()?;
    if let Some(g) = generated {
        clipboard::copy_and_clear_later(g.secret.expose_secret().as_bytes())?;
        eprintln!(
            "New password ({:.0} bits) copied; cleared in {} s.",
            g.entropy_bits,
            clipboard::CLEAR_AFTER_SECS
        );
    }
    Ok(())
}

/// Removes, then sets the extra fields named in `change`.
fn apply_fields(item: &mut Item, change: &Edit) -> Result<()> {
    for name in &change.rm_fields {
        let before = item.fields.len();
        item.fields.retain(|f| !f.name.eq_ignore_ascii_case(name));
        if item.fields.len() == before {
            return Err(format!("'{}' has no field {name}", item.title).into());
        }
    }
    let new_fields = change
        .fields
        .iter()
        .map(|n| (n, false))
        .chain(change.secret_fields.iter().map(|n| (n, true)));
    for (name, concealed) in new_fields {
        let prompt_text = format!("{name}: ");
        let value = if concealed {
            prompt::secret(&prompt_text)?.expose_secret().to_owned()
        } else {
            prompt::line(&prompt_text)?
        };
        if let Some(existing) = item
            .fields
            .iter_mut()
            .find(|f| f.name.eq_ignore_ascii_case(name))
        {
            existing.value = value;
            existing.concealed = concealed;
        } else {
            item.fields.push(Field {
                name: name.clone(),
                value,
                concealed,
            });
        }
    }
    Ok(())
}

/// The most an item's attachments may hold, raw. Base64 makes it 683 KiB,
/// inside the 1 MiB an item may be; the whole vault also travels to the
/// sync server on every change, so files belong here only when small.
const ATTACHMENTS_MAX: usize = 512 * 1024;

/// Removes, then attaches the files named in `change`.
fn apply_attachments(item: &mut Item, change: &Edit) -> Result<()> {
    for name in &change.rm_attachments {
        let before = item.attachments.len();
        item.attachments.retain(|a| a.name != *name);
        if item.attachments.len() == before {
            return Err(format!("'{}' has no attachment {name}", item.title).into());
        }
    }
    for path in &change.attach {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{} has no usable file name", path.display()))?
            .to_owned();
        let io = |e| error::Error::Io(path.clone(), e);
        let len = std::fs::metadata(path).map_err(io)?.len();
        let held: usize = item
            .attachments
            .iter()
            .filter(|a| a.name != name)
            .map(attachment_len)
            .sum();
        if usize::try_from(len).map_or(true, |len| held + len > ATTACHMENTS_MAX) {
            return Err(format!(
                "{name} would make the attachments of '{}' larger than {}; \
                 the whole vault travels on every sync, so only small files fit",
                item.title,
                human_bytes(ATTACHMENTS_MAX)
            )
            .into());
        }
        let bytes = zeroize::Zeroizing::new(std::fs::read(path).map_err(io)?);
        let data = Base64::encode_string(&bytes);
        let size = human_bytes(bytes.len());
        if let Some(existing) = item.attachments.iter_mut().find(|a| a.name == name) {
            existing.data = data;
            eprintln!("Replaced the attachment {name} ({size}).");
        } else {
            item.attachments.push(Attachment {
                name: name.clone(),
                data,
            });
            eprintln!("Attached {name} ({size}).");
        }
    }
    Ok(())
}

/// The raw size of an attachment, from its base64 length.
fn attachment_len(attachment: &Attachment) -> usize {
    let padding = attachment
        .data
        .bytes()
        .rev()
        .take_while(|&b| b == b'=')
        .count();
    attachment.data.len() / 4 * 3 - padding
}

fn human_bytes(n: usize) -> String {
    #[allow(clippy::cast_precision_loss)] // sizes far below 2^52
    match n {
        0..1024 => format!("{n} B"),
        1024..1_048_576 => format!("{:.1} KiB", n as f64 / 1024.0),
        _ => format!("{:.1} MiB", n as f64 / 1_048_576.0),
    }
}

/// `get --attachment`: writes the file, readable by this user only, to
/// `output` (a file, or a directory to put it in) or the current
/// directory. Never overwrites.
fn save_attachment(query: &str, name: &str, output: Option<&std::path::Path>) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let vault = unlock()?;
    let (_, item) = find(&vault, query)?;
    let Some(attachment) = item.attachments.iter().find(|a| a.name == name) else {
        let names: Vec<&str> = item.attachments.iter().map(|a| a.name.as_str()).collect();
        return Err(if names.is_empty() {
            format!("'{}' has no attachments", item.title)
        } else {
            format!(
                "'{}' has no attachment {name}; it has: {}",
                item.title,
                names.join(", ")
            )
        }
        .into());
    };
    let bytes = zeroize::Zeroizing::new(
        Base64::decode_vec(&attachment.data)
            .map_err(|_| format!("the attachment {name} is damaged"))?,
    );
    let path = match output {
        Some(p) if p.is_dir() => p.join(name),
        Some(p) => p.to_owned(),
        None => std::path::PathBuf::from(name),
    };
    let io = |e| error::Error::Io(path.clone(), e);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} already exists; choose another place with --output",
                    path.display()
                )
                .into()
            } else {
                io(e)
            }
        })?;
    file.write_all(&bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    eprintln!(
        "Saved {name} ({}) to {}, readable by you only.",
        human_bytes(bytes.len()),
        path.display()
    );
    Ok(())
}

/// The current code of an item and the seconds it stays valid.
fn totp_code(item: &Item) -> Result<(zeroize::Zeroizing<String>, u64)> {
    if item.totp.is_empty() {
        return Err(format!(
            "'{}' has no TOTP; add it with `passforme edit '{}' --totp`",
            item.title, item.title
        )
        .into());
    }
    let totp = Totp::parse(&item.totp).map_err(|e| e.to_string())?;
    let now = now();
    Ok((totp.code_at(now), totp.remaining(now)))
}

fn totp(query: &str) -> Result<()> {
    let vault = unlock()?;
    let (_, item) = find(&vault, query)?;
    let (code, remaining) = totp_code(&item)?;
    println!("{}", *code);
    eprintln!("valid for {remaining} s");
    Ok(())
}

fn passwd() -> Result<()> {
    let mut session = Session::open()?;
    let password = new_master_password()?;
    if session.store.sync_state()?.is_some() {
        sync::change_password(&mut session, &password, &KdfParams::DEFAULT)?;
    } else {
        eprintln!("Re-encrypting the vault under a new key...");
        session.vault.change_password(
            &password,
            &session.secret_key,
            &KdfParams::DEFAULT,
            &mut UnwrapErr(SysRng),
        )?;
        session.store.save_vault(session.vault.file())?;
    }
    // The backup would still open with the old password.
    session.store.remove_backup()?;
    // So would the open session.
    keeper::lock()?;
    eprintln!(
        "Master password changed. The Secret Key is unchanged. Older copies of the vault\n\
         file (backups) still open with the old password, but only as they were then."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_len_matches_the_decoded_bytes() {
        for len in 0..40 {
            let data = vec![7u8; len];
            let attachment = Attachment {
                name: "f".into(),
                data: Base64::encode_string(&data),
            };
            assert_eq!(attachment_len(&attachment), len);
        }
    }

    #[test]
    fn human_bytes_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2150), "2.1 KiB");
        assert_eq!(human_bytes(ATTACHMENTS_MAX), "512.0 KiB");
    }
}
