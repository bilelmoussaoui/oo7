use std::{
    fmt,
    io::{IsTerminal, Write},
    process::{ExitCode, Termination},
};

use clap::{Parser, Subcommand};
use oo7::{
    dbus::{Collection, Service},
    AsAttributes,
};

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
        #[arg(help = "List of attributes. This is a space separated list of pairs of key value", value_parser = parse_key_val::<String, String>)]
        attributes: Vec<(String, String)>,
    },

    #[command(
        name = "lookup",
        about = "Retrieve a secret",
        after_help = format!("Example:\n  {} lookup smtp-port=1025", BINARY_NAME)
    )]
    Lookup {
        #[arg(help = "List of attributes. This is a space separated list of pairs of key value", value_parser = parse_key_val::<String, String>)]
        attributes: Vec<(String, String)>,
        #[arg(long, help = "Print only the secret.")]
        secret_only: bool,
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
        #[arg(help = "List of attributes. This is a space separated list of pairs of key value", value_parser = parse_key_val::<String, String>)]
        attributes: Vec<(String, String)>,
        #[arg(long, help = "Print only the secret.")]
        secret_only: bool,
    },

    #[command(
        name = "store",
        about = "Store a secret",
        after_help = format!("The contents of the secret will be asked afterwards.\n\nExample:\n  {} store 'My Personal Mail' smtp-port=1025 imap-port=143", BINARY_NAME)
    )]
    Store {
        #[arg(help = "Description for the secret")]
        label: String,
        #[arg(help = "List of attributes. This is a space separated list of pairs of key value", value_parser = parse_key_val::<String, String>)]
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Store { label, attributes } => store(&label, &attributes).await,
        Commands::Lookup {
            attributes,
            secret_only,
        } => lookup(&attributes, secret_only).await,
        Commands::Search {
            attributes,
            all,
            secret_only,
        } => search(&attributes, all, secret_only).await,
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

    print!("Type a secret: ");
    std::io::stdout()
        .flush()
        .map_err(|_| Error::new("Could not flush stdout"))?;
    let secret = rpassword::read_password().map_err(|_| Error::new("Can't read password"))?;

    collection
        .create_item(label, attributes, &secret, true, "text/plain")
        .await?;

    Ok(())
}

async fn lookup(attributes: &impl AsAttributes, secret_only: bool) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    if let Some(item) = items.first() {
        print_item(item, secret_only).await?;
    }

    Ok(())
}

async fn search(attributes: &impl AsAttributes, all: bool, secret_only: bool) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    if all {
        for item in items {
            print_item(&item, secret_only).await?;
        }
    } else if let Some(item) = items.first() {
        print_item(item, secret_only).await?;
    }

    Ok(())
}

async fn delete(attributes: &impl AsAttributes) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    for item in items {
        item.delete().await?;
    }

    Ok(())
}

async fn lock() -> Result<(), Error> {
    let collection = collection().await?;
    collection.lock().await?;

    Ok(())
}

async fn unlock() -> Result<(), Error> {
    let collection = collection().await?;
    collection.unlock().await?;

    Ok(())
}

async fn print_item<'a>(item: &oo7::dbus::Item<'a>, secret_only: bool) -> Result<(), Error> {
    use std::fmt::Write;
    if secret_only {
        let bytes = item.secret().await?;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&bytes)?;
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

        let created = chrono::DateTime::<chrono::Utc>::from_timestamp(created.as_secs() as i64, 0)
            .unwrap()
            .with_timezone(&chrono::Local);
        let modified =
            chrono::DateTime::<chrono::Utc>::from_timestamp(modified.as_secs() as i64, 0)
                .unwrap()
                .with_timezone(&chrono::Local);

        let mut result = format!("[{label}]\n");
        match std::str::from_utf8(&bytes) {
            Ok(secret) => {
                writeln!(&mut result, "secret = {secret}").unwrap();
            }
            Err(_) => {
                writeln!(&mut result, "secret = {:02X?}", bytes.as_slice()).unwrap();
            }
        }

        writeln!(
            &mut result,
            "created = {}",
            created.format("%Y-%m-%d %H:%M:%S")
        )
        .unwrap();
        writeln!(
            &mut result,
            "modified = {}",
            modified.format("%Y-%m-%d %H:%M:%S")
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
    let collection = match service.default_collection().await {
        Ok(c) => Ok(c),
        Err(oo7::dbus::Error::NotFound(_)) => {
            service
                .create_collection("Login", Some(oo7::dbus::DEFAULT_COLLECTION))
                .await
        }
        Err(e) => Err(e),
    }?;

    Ok(collection)
}
