use std::{
    fmt,
    io::{BufRead, IsTerminal, Write},
    process::{ExitCode, Termination},
};

use clap::{Parser, Subcommand};
use oo7::{
    dbus::{Collection, Service},
    AsAttributes,
};
use time::{OffsetDateTime, UtcOffset};

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

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

#[derive(Subcommand)]
enum Commands {
    #[command(
        name = "delete",
        about = "Delete a secret",
        after_help = format!("Will delete all secrets with matching attributes.\n\nExample:\n  {} delete smtp-port=1025", BINARY_NAME)
    )]
    Delete {
        #[arg(
            help = "List of attributes. This is a space separated list of pairs of key value",
            value_parser = parse_key_val::<String, String>,
            required = true, num_args = 1
        )]
        attributes: Vec<(String, String)>,
    },

    #[command(
        name = "lookup",
        about = "Retrieve a secret",
        after_help = format!("Examples:\n  {} lookup smtp-port=1025\n  {0} lookup --secret-only mysql-port=1234 | systemd-creds encrypt --name=mysql-password -p - -", BINARY_NAME)
    )]
    Lookup {
        #[arg(
            help = "List of attributes. This is a space separated list of pairs of key value",
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
        after_help = format!("Example:\n  {} search --all smtp-port=1025", BINARY_NAME)
    )]
    Search {
        #[arg(
            short,
            long,
            help = "Whether to list all possible matches or only the first result"
        )]
        all: bool,
        #[arg(
            help = "List of attributes. This is a space separated list of pairs of key value",
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
        after_help = format!("The contents of the secret will be asked afterwards or read from stdin.\n\nExamples:\n  {} store 'My Personal Mail' smtp-port=1025 imap-port=143\n  systemd-ask-password -n | {0} store 'My Secret' lang=en", BINARY_NAME)
    )]
    Store {
        #[arg(help = "Description for the secret")]
        label: String,
        #[arg(
            help = "List of attributes. This is a space separated list of pairs of key value",
            value_parser = parse_key_val::<String, String>,
            required = true, num_args = 1
        )]
        attributes: Vec<(String, String)>,
    },

    #[command(name = "lock", about = "Lock the keyring")]
    Lock,

    #[command(name = "unlock", about = "Unlock the keyring")]
    Unlock,
}

#[derive(Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Store { label, attributes } => store(&label, &attributes).await,
        Commands::Lookup {
            attributes,
            secret_only,
            hex,
        } => lookup(&attributes, secret_only, hex).await,
        Commands::Search {
            attributes,
            all,
            secret_only,
            hex,
        } => search(&attributes, all, secret_only, hex).await,
        Commands::Delete { attributes } => delete(&attributes).await,
        Commands::Lock => lock().await,
        Commands::Unlock => unlock().await,
    }
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

async fn store(label: &str, attributes: &impl AsAttributes) -> Result<(), Error> {
    let collection = collection().await?;

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

    collection
        .create_item(label, attributes, &secret, true, "text/plain", None)
        .await?;

    Ok(())
}

async fn lookup(
    attributes: &impl AsAttributes,
    secret_only: bool,
    as_hex: bool,
) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    if let Some(item) = items.first() {
        print_item(item, secret_only, as_hex).await?;
    }

    Ok(())
}

async fn search(
    attributes: &impl AsAttributes,
    all: bool,
    secret_only: bool,
    as_hex: bool,
) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    if all {
        for item in items {
            print_item(&item, secret_only, as_hex).await?;
        }
    } else if let Some(item) = items.first() {
        print_item(item, secret_only, as_hex).await?;
    }

    Ok(())
}

async fn delete(attributes: &impl AsAttributes) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    for item in items {
        item.delete(None).await?;
    }

    Ok(())
}

async fn lock() -> Result<(), Error> {
    let collection = collection().await?;
    collection.lock(None).await?;

    Ok(())
}

async fn unlock() -> Result<(), Error> {
    let collection = collection().await?;
    collection.unlock(None).await?;

    Ok(())
}

async fn print_item<'a>(
    item: &oo7::dbus::Item<'a>,
    secret_only: bool,
    as_hex: bool,
) -> Result<(), Error> {
    use std::fmt::Write;
    if secret_only {
        let bytes = item.secret().await?;
        let mut stdout = std::io::stdout().lock();
        if as_hex {
            let hex = hex::encode(&bytes);
            stdout.write_all(hex.as_bytes())?;
        } else {
            stdout.write_all(&bytes)?;
        }
        // Add a new line if we are writing to a tty
        if stdout.is_terminal() {
            stdout.write_all(b"\n")?;
        }
    } else {
        let label = item.label().await?;
        let bytes = item.secret().await?;
        let mut attributes = item.attributes().await?;
        let created = item.created().await?;
        let modified = item.modified().await?;
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
            let hex = hex::encode(&bytes);
            writeln!(&mut result, "secret = {hex}").unwrap();
        } else {
            match std::str::from_utf8(&bytes) {
                Ok(secret) => {
                    writeln!(&mut result, "secret = {secret}").unwrap();
                }
                Err(_) => {
                    let hex = hex::encode(&bytes);
                    writeln!(&mut result, "secret = {hex}").unwrap();
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
        if let Some(schema) = attributes.remove("xdg:schema") {
            writeln!(&mut result, "schema = {schema} ").unwrap();
        }
        writeln!(&mut result, "attributes = {attributes:?} ").unwrap();
        print!("{result}");
    }
    Ok(())
}

async fn collection<'a>() -> Result<Collection<'a>, Error> {
    let service = Service::new().await?;
    let collection = service.default_collection().await?;

    Ok(collection)
}
