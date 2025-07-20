use std::{
    collections::HashMap,
    fmt,
    io::{BufRead, IsTerminal, Write},
    path::PathBuf,
    process::{ExitCode, Termination},
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use oo7::dbus::Service;
use time::{OffsetDateTime, UtcOffset};

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const H_STYLE: anstyle::Style = anstyle::Style::new().bold().underline();

struct Error(String);

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error(err.to_string())
    }
}

impl From<oo7::file::Error> for Error {
    fn from(err: oo7::file::Error) -> Error {
        Error(err.to_string())
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(err: oo7::dbus::Error) -> Error {
        Error(err.to_string())
    }
}

impl Error {
    fn new(s: &str) -> Self {
        Self(String::from(s))
    }
}

impl Termination for Error {
    fn report(self) -> ExitCode {
        ExitCode::FAILURE
    }
}

enum Keyring {
    File(oo7::file::UnlockedKeyring),
    Collection(oo7::dbus::Collection<'static>),
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        name = "delete",
        about = "Delete a secret",
        after_help = format!("Will delete all secrets with matching attributes.\n\n{H_STYLE}Example:{H_STYLE:#}\n  {} delete smtp-port=1025", BINARY_NAME)
    )]
    Delete {
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>,
            required = true, num_args = 1
        )]
        attributes: Vec<(String, String)>,
    },

    #[command(
        name = "lookup",
        about = "Retrieve a secret",
        after_help = format!("{H_STYLE}Examples:{H_STYLE:#}\n  {} lookup smtp-port=1025\n  {0} lookup --secret-only mysql-port=1234 | systemd-creds encrypt --name=mysql-password -p - -", BINARY_NAME)
    )]
    Lookup {
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>,
            required = true,
            num_args = 1
        )]
        attributes: Vec<(String, String)>,
        #[arg(long, help = "Print only the secret.")]
        secret_only: bool,
        #[arg(long, help = "Print the secret in hexadecimal.")]
        hex: bool,
    },

    #[command(
        name = "search",
        about = "Search entries with matching attributes",
        after_help = format!("{H_STYLE}Example:{H_STYLE:#}\n  {} search --all smtp-port=1025", BINARY_NAME)
    )]
    Search {
        #[arg(
            short,
            long,
            help = "Whether to list all possible matches or only the first result"
        )]
        all: bool,
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>
        )]
        attributes: Vec<(String, String)>,
        #[arg(long, help = "Print only the secret.")]
        secret_only: bool,
        #[arg(long, help = "Print the secret in hexadecimal.")]
        hex: bool,
    },

    #[command(
        name = "store",
        about = "Store a secret",
        after_help = format!("The contents of the secret will be asked afterwards or read from stdin.\n\n{H_STYLE}Examples:{H_STYLE:#}\n  {} store 'My Personal Mail' smtp-port=1025 imap-port=143\n  systemd-ask-password -n | {0} store 'My Secret' lang=en", BINARY_NAME)
    )]
    Store {
        #[arg(help = "Description for the secret")]
        label: String,
        #[arg(
            help = "List of attributes. This is a space-separated list of pairs key=value",
            value_parser = parse_key_val::<String, String>,
            required = true, num_args = 1
        )]
        attributes: Vec<(String, String)>,
    },

    #[command(name = "list", about = "List all the items in the keyring")]
    List {
        #[arg(long, help = "Print the secret in hexadecimal.")]
        hex: bool,
    },

    #[command(name = "lock", about = "Lock the keyring")]
    Lock,

    #[command(name = "unlock", about = "Unlock the keyring")]
    Unlock,

    #[command(name = "repair", about = "Repair the keyring")]
    Repair,
}

impl Commands {
    async fn execute(self, args: Arguments) -> Result<(), Error> {
        let service = Service::new().await?;
        if args.app_id.is_some() && args.keyring.is_some() {
            return Err(Error::new(
                "Only one of application ID or keyring can be specified at a time.",
            ));
        }
        // We get the secret first from the app-id, then if the --keyring is set, we try
        // to use the --secret variable.
        let (secret, path) = if let Some(app_id) = &args.app_id {
            let attributes = HashMap::from([("app_id", app_id)]);
            let default_collection = service.default_collection().await?;
            let secret =
                if let Some(item) = default_collection.search_items(&attributes).await?.first() {
                    item.secret().await?
                } else {
                    return Err(Error::new(
                        "The application doesn't have a stored key on the host keyring.",
                    ));
                };

            // That is the path used by libsecret/oo7, how does it work with kwallet for
            // example?
            let path = home().map(|mut path| {
                path.push(".var/app");
                path.push(app_id.to_string());
                path.push("data/keyrings/default.keyring");
                path
            });
            (Some(secret), path)
        } else if let Some(keyring) = args.keyring {
            (args.secret, Some(keyring))
        } else if let Some(secret) = args.secret {
            (
                Some(secret),
                data_dir().map(|mut path| {
                    path.push("keyrings/default.keyring");
                    path
                }),
            )
        } else {
            (None, None)
        };

        let keyring = match (path, secret) {
            (Some(path), Some(secret)) => {
                Keyring::File(oo7::file::UnlockedKeyring::load(path, secret).await?)
            }
            (Some(_), None) => {
                return Err(Error::new("A keyring requires a secret."));
            }
            (None, Some(_)) => {
                return Err(Error::new("A secret requires a keyring."));
            }
            _ => {
                let collection = if let Some(alias) = &args.collection {
                    service
                        .with_alias(alias)
                        .await?
                        .ok_or_else(|| Error(format!("Collection '{alias}' not found")))?
                } else {
                    service.default_collection().await?
                };
                Keyring::Collection(collection)
            }
        };

        match self {
            Commands::Delete { attributes } => match keyring {
                Keyring::Collection(collection) => {
                    let items = collection.search_items(&attributes).await?;
                    for item in items {
                        item.delete(None).await?;
                    }
                }
                Keyring::File(keyring) => {
                    keyring.delete(&attributes).await?;
                }
            },
            Commands::Lookup {
                attributes,
                secret_only,
                hex,
            } => match keyring {
                Keyring::Collection(collection) => {
                    let items = collection.search_items(&attributes).await?;

                    if let Some(item) = items.first() {
                        print_item_dbus(item, secret_only, hex).await?;
                    }
                }
                Keyring::File(keyring) => {
                    let items = keyring.search_items(&attributes).await?;
                    if let Some(item) = items.first() {
                        print_item_keyring(item, secret_only, hex)?;
                    }
                }
            },
            Commands::Search {
                all,
                attributes,
                secret_only,
                hex,
            } => match keyring {
                Keyring::File(keyring) => {
                    let items = keyring.search_items(&attributes).await?;
                    if all {
                        for item in items {
                            print_item_keyring(&item, secret_only, hex)?;
                        }
                    } else if let Some(item) = items.first() {
                        print_item_keyring(item, secret_only, hex)?;
                    }
                }
                Keyring::Collection(collection) => {
                    let items = collection.search_items(&attributes).await?;

                    if all {
                        for item in items {
                            print_item_dbus(&item, secret_only, hex).await?;
                        }
                    } else if let Some(item) = items.first() {
                        print_item_dbus(item, secret_only, hex).await?;
                    }
                }
            },
            Commands::Store { label, attributes } => {
                let mut stdin = std::io::stdin().lock();
                let secret = if stdin.is_terminal() {
                    print!("Type a secret: ");
                    std::io::stdout()
                        .flush()
                        .map_err(|_| Error::new("Could not flush stdout"))?;
                    rpassword::read_password().map_err(|_| Error::new("Can't read password"))?
                } else {
                    let mut secret = String::new();
                    stdin.read_line(&mut secret)?;
                    secret
                };

                match keyring {
                    Keyring::File(keyring) => {
                        keyring
                            .create_item(&label, &attributes, secret, true)
                            .await?;
                    }
                    Keyring::Collection(collection) => {
                        collection
                            .create_item(&label, &attributes, secret, true, None)
                            .await?;
                    }
                }
            }
            Commands::List { hex } => match keyring {
                Keyring::File(keyring) => {
                    let items = keyring.items().await?;
                    for item in items {
                        if let Ok(item) = item {
                            print_item_keyring(&item, false, hex)?;
                        } else {
                            println!("Item is not valid and cannot be decrypted");
                        }
                    }
                }
                Keyring::Collection(collection) => {
                    let items = collection.items().await?;
                    for item in items {
                        print_item_dbus(&item, false, hex).await?;
                    }
                }
            },
            Commands::Lock => match keyring {
                Keyring::File(_) => {
                    return Err(Error::new("Keyring file doesn't support locking."));
                }
                Keyring::Collection(collection) => {
                    collection.lock(None).await?;
                }
            },
            Commands::Unlock => match keyring {
                Keyring::File(_) => {
                    return Err(Error::new("Keyring file doesn't support unlocking."));
                }
                Keyring::Collection(collection) => {
                    collection.unlock(None).await?;
                }
            },
            Commands::Repair => match keyring {
                Keyring::File(keyring) => {
                    let deleted_items = keyring.delete_broken_items().await?;
                    println!("{deleted_items} broken items were deleted");
                }
                Keyring::Collection(_) => {
                    return Err(Error::new("Only a keyring file can be repaired."));
                }
            },
        };
        Ok(())
    }
}

#[derive(Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[command(flatten)]
    args: Arguments,
}

#[derive(Args)]
struct Arguments {
    #[arg(
        name = "collection",
        short,
        long,
        global = true,
        help = "Specify a collection. The default collection will be used if not specified"
    )]
    collection: Option<String>,
    #[arg(
        name = "keyring",
        short,
        long,
        global = true,
        help = "Specify a keyring. The default collection will be used if not specified"
    )]
    keyring: Option<PathBuf>,
    #[arg(
        name = "secret",
        short,
        long,
        global = true,
        help = "Specify the keyring secret. The default collection will be used if not specified"
    )]
    secret: Option<oo7::Secret>,
    #[arg(
        name = "app-id",
        long,
        global = true,
        help = "Specify a sandboxed application ID. The default collection will be used if not specified"
    )]
    app_id: Option<oo7::ashpd::AppID>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    cli.command.execute(cli.args).await
}

// Source <https://github.com/clap-rs/clap/blob/master/examples/typed-derive.rs#L48>
fn parse_key_val<T, U>(
    s: &str,
) -> Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("Invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

fn print_item_common(
    secret: &oo7::Secret,
    label: &str,
    mut attributes: HashMap<String, String>,
    created: Duration,
    modified: Duration,
    secret_only: bool,
    as_hex: bool,
) -> Result<(), Error> {
    use std::fmt::Write;
    let bytes = secret.as_bytes();
    if secret_only {
        let mut stdout = std::io::stdout().lock();
        if as_hex {
            let hex = hex::encode(bytes);
            stdout.write_all(hex.as_bytes())?;
        } else {
            stdout.write_all(bytes)?;
        }
        // Add a new line if we are writing to a tty
        if stdout.is_terminal() {
            stdout.write_all(b"\n")?;
        }
    } else {
        let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

        let created = OffsetDateTime::from_unix_timestamp(created.as_secs() as i64)
            .unwrap()
            .to_offset(local_offset);
        let modified = OffsetDateTime::from_unix_timestamp(modified.as_secs() as i64)
            .unwrap()
            .to_offset(local_offset);

        let mut result = format!("[{label}]\n");

        // we still fallback to hex if it is not a string
        if as_hex {
            let hex = hex::encode(bytes);
            writeln!(&mut result, "hex encoded secret = {hex}").unwrap();
        } else {
            match std::str::from_utf8(bytes) {
                Ok(secret) => {
                    writeln!(&mut result, "secret = {secret}").unwrap();
                }
                Err(_) => {
                    let hex = hex::encode(bytes);
                    writeln!(&mut result, "hex encoded secret = {hex}").unwrap();
                }
            }
        }

        let format = time::format_description::parse_borrowed::<2>(
            "[year]-[month]-[day] [hour]:[minute]:[second]",
        )
        .unwrap();

        writeln!(
            &mut result,
            "created = {}",
            created.format(&format).unwrap()
        )
        .unwrap();
        writeln!(
            &mut result,
            "modified = {}",
            modified.format(&format).unwrap()
        )
        .unwrap();
        if let Some(schema) = attributes.remove(oo7::XDG_SCHEMA_ATTRIBUTE) {
            writeln!(&mut result, "schema = {schema} ").unwrap();
        }
        if let Some(content_type) = attributes.remove(oo7::CONTENT_TYPE_ATTRIBUTE) {
            writeln!(&mut result, "content_type = {content_type} ").unwrap();
        }
        writeln!(&mut result, "attributes = {attributes:?} ").unwrap();
        print!("{result}");
    }
    Ok(())
}

fn print_item_keyring(
    item: &oo7::file::UnlockedItem,
    secret_only: bool,
    as_hex: bool,
) -> Result<(), Error> {
    let secret = item.secret();
    let label = item.label();
    let attributes = item
        .attributes()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<HashMap<String, String>>();
    let created = item.created();
    let modified = item.modified();
    print_item_common(
        &secret,
        label,
        attributes,
        created,
        modified,
        secret_only,
        as_hex,
    )?;
    Ok(())
}

async fn print_item_dbus(
    item: &oo7::dbus::Item<'_>,
    secret_only: bool,
    as_hex: bool,
) -> Result<(), Error> {
    let secret = item.secret().await?;
    let label = item.label().await?;
    let attributes = item.attributes().await?;
    let created = item.created().await?;
    let modified = item.modified().await?;

    print_item_common(
        &secret,
        &label,
        attributes,
        created,
        modified,
        secret_only,
        as_hex,
    )?;

    Ok(())
}

// Copy from /client/src/file/api/mod.rs
fn data_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .and_then(|h| if h.is_empty() { None } else { Some(h) })
        .map(PathBuf::from)
        .and_then(|p| if p.is_absolute() { Some(p) } else { None })
        .or_else(|| home().map(|p| p.join(".local/share")))
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .and_then(|h| if h.is_empty() { None } else { Some(h) })
        .map(PathBuf::from)
}
