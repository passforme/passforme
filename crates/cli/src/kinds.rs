//! Kinds of item at the command line: asking for what a kind holds,
//! checking what can be checked, and finding a field by name for `get --field`.

use std::path::Path;

use passforme_core::bip39;
use passforme_core::generator::Generated;
use passforme_core::item::{Field, Item};
use passforme_core::kind::{self, Code, Kind, Slot};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::{GenArgs, prompt};

pub fn parse(name: &str) -> Result<Kind> {
    Kind::from_name(name)
        .ok_or_else(|| format!("unknown kind '{name}'; `passforme kinds` lists them").into())
}

pub fn print_all() {
    for kind in Kind::ALL {
        println!("{:<19} {}", kind.name(), kind.about());
    }
}

/// What the command line already gave for a new item.
pub struct Given<'a> {
    pub username: Option<String>,
    pub urls: Vec<String>,
    pub generate: Option<&'a GenArgs>,
    /// The main secret read from a file (a private key).
    pub file: Option<&'a Path>,
}

/// Refuses options the kind has no slot for, before the vault is opened:
/// otherwise `add X --kind pin --username me` would drop the username
/// silently. `--generate` only fits kinds whose secret is a password; a
/// generated PIN, card number or recovery phrase would be nonsense.
pub fn check_given(kind: Kind, given: &Given<'_>) -> Result<()> {
    let name = kind.name();
    let mut wrong = Vec::new();
    if given.username.is_some() && kind.username_label().is_none() {
        wrong.push("--username");
    }
    if !given.urls.is_empty() && !kind.slots().contains(&Slot::Urls) {
        wrong.push("--url");
    }
    if given.file.is_some() && kind.password_label().is_none() {
        wrong.push("--file");
    }
    if given.generate.is_some() && !generates(kind) {
        wrong.push("--generate");
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{name} items take no {}; `passforme kinds` shows what each kind holds",
            wrong.join(", ")
        )
        .into())
    }
}

/// Whether the kind's main secret is a password the generator can make.
pub fn generates(kind: Kind) -> bool {
    matches!(kind, Kind::Login | Kind::Wifi | Kind::Bank | Kind::Other)
}

/// Fills a new item of `item.kind` slot by slot, asking for what was not
/// given; every prompt may be left empty. Returns the generated secret, if
/// any, for the caller to copy once the item is saved.
pub fn fill(item: &mut Item, given: Given<'_>) -> Result<Option<Generated>> {
    let kind = item.kind;
    eprintln!("New {}: Enter skips a field.", kind.name());
    let mut generated = None;
    let mut username = given.username;
    let mut urls = given.urls;
    for slot in kind.slots() {
        match *slot {
            Slot::Username(label) => {
                item.username = match username.take() {
                    Some(u) => u,
                    None => prompt::line(&format!("{label}: "))?.trim().to_owned(),
                };
            }
            Slot::Password(label) => {
                let secret = if let Some(path) = given.file {
                    Zeroizing::new(read_secret_file(path)?)
                } else if let Some(spec) = given.generate {
                    let g = spec.generate()?;
                    let secret = Zeroizing::new(g.secret.expose_secret().to_owned());
                    generated = Some(g);
                    secret
                } else {
                    Zeroizing::new(
                        prompt::secret(&format!("{label}: "))?
                            .expose_secret()
                            .trim()
                            .to_owned(),
                    )
                };
                item.password = check_secret(kind, &secret)?;
            }
            Slot::Urls => {
                if urls.is_empty() {
                    let url = prompt::line("URL: ")?;
                    if !url.trim().is_empty() {
                        urls.push(url.trim().to_owned());
                    }
                }
                item.urls = std::mem::take(&mut urls);
            }
            // Only logins have it, and they keep `edit --totp`.
            Slot::Totp => {}
            Slot::Field { name, concealed } => {
                let value = ask_field(name, concealed)?;
                if !value.is_empty() {
                    check_field(kind, name, &value)?;
                    item.fields.push(Field {
                        name: name.to_owned(),
                        value: value.to_string(),
                        concealed,
                    });
                }
            }
            Slot::Questions => {
                eprintln!("Questions and answers; an empty question finishes.");
                loop {
                    let question = prompt::line("Question: ")?;
                    let question = question.trim();
                    if question.is_empty() {
                        break;
                    }
                    let answer = prompt::secret("Answer: ")?;
                    item.fields.push(Field {
                        name: question.to_owned(),
                        value: answer.expose_secret().to_owned(),
                        concealed: true,
                    });
                }
            }
            Slot::Codes => item.codes = read_codes()?,
            // Last by construction: it reads up to the end of input.
            Slot::Notes => {
                prompt::multiline("Text (finish with Ctrl-D on an empty line):")?
                    .trim_end()
                    .clone_into(&mut item.notes);
            }
        }
    }
    Ok(generated)
}

fn ask_field(name: &str, concealed: bool) -> Result<Zeroizing<String>> {
    let text = format!("{name}: ");
    Ok(if concealed {
        Zeroizing::new(prompt::secret(&text)?.expose_secret().trim().to_owned())
    } else {
        Zeroizing::new(prompt::line(&text)?.trim().to_owned())
    })
}

/// A key file as it is (a private key needs its final newline back).
fn read_secret_file(path: &Path) -> Result<String> {
    let bytes = Zeroizing::new(
        std::fs::read(path).map_err(|e| crate::error::Error::Io(path.to_owned(), e))?,
    );
    String::from_utf8(bytes.to_vec()).map_err(|_| format!("{} is not text", path.display()).into())
}

/// The main secret, normalized and checked where the kind allows it.
fn check_secret(kind: Kind, secret: &str) -> Result<String> {
    match kind {
        Kind::CryptoSeed if !secret.is_empty() => {
            let words = bip39::normalize(secret);
            match bip39::check(&words) {
                Ok(list) => eprintln!("Recovery phrase checks ({list:?} BIP-39 list)."),
                Err(e) => confirm(&format!("The recovery phrase does not check: {e}."))?,
            }
            Ok(words.to_string())
        }
        // A service's phrase may or may not be BIP-39 (Proton's is): checked
        // only when its length says it could be, and kept as typed otherwise.
        Kind::RecoveryPhrase if !secret.is_empty() => {
            let words = bip39::normalize(secret);
            match bip39::check(&words) {
                Ok(list) => {
                    eprintln!("Recovery phrase checks ({list:?} BIP-39 list).");
                    Ok(words.to_string())
                }
                Err(bip39::SeedError::WordCount(_)) => Ok(secret.to_owned()),
                Err(e) => {
                    confirm(&format!(
                        "The phrase does not check as BIP-39: {e} (fine if the service \
                         does not use BIP-39)."
                    ))?;
                    Ok(secret.to_owned())
                }
            }
        }
        Kind::Card if !secret.is_empty() => {
            if !kind::luhn_ok(secret) {
                confirm("The card number fails its check digit (a typo?).")?;
            }
            Ok(secret.to_owned())
        }
        _ => Ok(secret.to_owned()),
    }
}

fn check_field(kind: Kind, name: &str, value: &str) -> Result<()> {
    if kind == Kind::Card && name == "Expiry" && !kind::expiry_ok(value) {
        confirm("The expiry is not MM/YY.")?;
    }
    Ok(())
}

/// Asks before keeping something that looks wrong; no means stop.
fn confirm(problem: &str) -> Result<()> {
    let answer = prompt::line(&format!("{problem} Save it anyway? [y/N] "))?;
    if answer.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err("nothing saved".into())
    }
}

/// Recovery codes, one per line (a code may contain spaces, as Google's
/// do), read without echo until an empty line.
pub fn read_codes() -> Result<Vec<Code>> {
    eprintln!("Paste the codes, one per line, then an empty line (nothing is shown):");
    let mut codes = Vec::new();
    loop {
        let line = prompt::secret("")?;
        let code = line.expose_secret().trim();
        if code.is_empty() {
            break;
        }
        codes.push(Code {
            code: code.to_owned(),
            used: false,
        });
    }
    eprintln!("{} code(s).", codes.len());
    Ok(codes)
}

/// A field of `item` by name, or its main secret when `None`. Names are
/// case-insensitive: `password`, `username`, `url`, `totp`, the kind's own
/// labels (`pin`, `key`, `number`, `words`…) and any extra field.
pub fn lookup(item: &Item, name: Option<&str>) -> Result<(String, Zeroizing<String>)> {
    let kind = item.kind;
    let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) else {
        return main_secret(item);
    };
    let secret_label = kind.password_label().unwrap_or("password");
    let user_label = kind.username_label().unwrap_or("username");
    let found = if ["password", "secret"]
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
        || secret_label.eq_ignore_ascii_case(name)
    {
        Some((secret_label.to_owned(), item.password.clone()))
    } else if ["username", "user"]
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
        || user_label.eq_ignore_ascii_case(name)
    {
        Some((user_label.to_owned(), item.username.clone()))
    } else if name.eq_ignore_ascii_case("url") {
        Some((
            "URL".to_owned(),
            item.urls.first().cloned().unwrap_or_default(),
        ))
    } else if name.eq_ignore_ascii_case("totp") {
        Some((
            "TOTP code".to_owned(),
            crate::totp_code(item)?.0.to_string(),
        ))
    } else {
        item.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| (f.name.clone(), f.value.clone()))
    };
    match found {
        Some((label, value)) if !value.is_empty() => Ok((label, Zeroizing::new(value))),
        _ => Err(format!(
            "'{}' has no {name}; it has: {}",
            item.title,
            field_names(item).join(", ")
        )
        .into()),
    }
}

/// What `get` copies without `--field`: the main secret, or for kinds without
/// one (a document) the first field the kind asks for.
fn main_secret(item: &Item) -> Result<(String, Zeroizing<String>)> {
    if item.kind == Kind::RecoveryCodes {
        return Err(format!("for '{}' use `passforme codes`", item.title).into());
    }
    if !item.password.is_empty() {
        let label = item.kind.password_label().unwrap_or("password");
        return Ok((label.to_owned(), Zeroizing::new(item.password.clone())));
    }
    for slot in item.kind.slots() {
        if let Slot::Field { name, .. } = slot
            && let Some(f) = item
                .fields
                .iter()
                .find(|f| f.name == *name && !f.value.is_empty())
        {
            return Ok((f.name.clone(), Zeroizing::new(f.value.clone())));
        }
    }
    Err(format!(
        "'{}' has no secret to copy; choose one with --field: {}",
        item.title,
        field_names(item).join(", ")
    )
    .into())
}

/// The names `--field` accepts for this item, for error messages.
fn field_names(item: &Item) -> Vec<String> {
    let mut names = Vec::new();
    if !item.password.is_empty() {
        names.push(
            item.kind
                .password_label()
                .unwrap_or("password")
                .to_lowercase(),
        );
    }
    if !item.username.is_empty() {
        names.push(
            item.kind
                .username_label()
                .unwrap_or("username")
                .to_lowercase(),
        );
    }
    if !item.urls.is_empty() {
        names.push("url".to_owned());
    }
    if !item.totp.is_empty() {
        names.push("totp".to_owned());
    }
    names.extend(item.fields.iter().map(|f| f.name.to_lowercase()));
    if names.is_empty() {
        names.push("(nothing)".to_owned());
    }
    names
}
