use std::{
    collections::HashMap,
    fmt,
    io::Write,
    process::{ExitCode, Termination},
};

use clap::{Command, CommandFactory, FromArgMatches, Parser};
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

#[derive(Parser)]
#[command(
    name = "store",
    about = "Store a secret",
    after_help = format!("The contents of the secret will be asked afterwards.\n\nExample:\n  {} store 'My Personal Mail' smtp-port 1025 imap-port 143", BINARY_NAME)
)]
struct StoreArgs {
    #[clap(help = "Description for the secret")]
    label: String,
    #[clap(help = "List of attributes. This is a space separated list of pairs of key value")]
    attributes: Vec<String>,
}

#[derive(Parser)]
#[command(
    name = "search",
    about = "Search entries with matching attributes",
    after_help = format!("Example:\n  {} search --all smtp-port 1025", BINARY_NAME)
)]
struct SearchArgs {
    #[clap(help = "List of attributes. This is a space separated list of pairs of key value")]
    attributes: Vec<String>,
    #[clap(
        short,
        long,
        help = "Whether to list all possible matches or only the first result"
    )]
    all: bool,
}

#[derive(Parser)]
#[command(
    name = "lookup",
    about = "Retrieve a secret",
    after_help = format!("Example:\n  {} lookup smtp-port 1025", BINARY_NAME)
)]
struct LookupArgs {
    #[clap(help = "List of attributes. This is a space separated list of pairs of key value")]
    attributes: Vec<String>,
}

#[derive(Parser)]
#[command(
    name = "delete",
    about = "Delete a secret",
    after_help = format!("Will delete all secrets with matching attributes.\n\nExample:\n  {} delete smtp-port 1025", BINARY_NAME)
)]
struct DeleteArgs {
    #[clap(help = "List of attributes. This is a space separated list of pairs of key value")]
    attributes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cmd = Command::new(BINARY_NAME)
        .bin_name(BINARY_NAME)
        .subcommand_required(true)
        .subcommand(StoreArgs::command())
        .subcommand(LookupArgs::command())
        .subcommand(DeleteArgs::command())
        .subcommand(SearchArgs::command())
        .subcommand(Command::new("lock").about("Lock the keyring"))
        .subcommand(Command::new("unlock").about("Unlock the keyring"));
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("store", matches)) => {
            let args =
                StoreArgs::from_arg_matches(matches).map_err(|e| Error::new(&e.to_string()))?;
            let attributes = parse_attributes(&args.attributes)?;

            store(&args.label, &attributes).await
        }
        Some(("lookup", matches)) => {
            let args =
                LookupArgs::from_arg_matches(matches).map_err(|e| Error::new(&e.to_string()))?;
            let attributes = parse_attributes(&args.attributes)?;

            lookup(&attributes).await
        }
        Some(("search", matches)) => {
            let args =
                SearchArgs::from_arg_matches(matches).map_err(|e| Error::new(&e.to_string()))?;
            let attributes = parse_attributes(&args.attributes)?;

            search(&attributes, args.all).await
        }
        Some(("delete", matches)) => {
            let args =
                LookupArgs::from_arg_matches(matches).map_err(|e| Error::new(&e.to_string()))?;
            let attributes = parse_attributes(&args.attributes)?;

            delete(&attributes).await
        }
        Some(("lock", _matches)) => lock().await,
        Some(("unlock", _matches)) => unlock().await,
        _ => unreachable!("clap should ensure we don't get here"),
    }
}

fn parse_attributes(attributes: &[String]) -> Result<HashMap<String, String>, Error> {
    // Should this allow attribute-less secrets?
    let mut attributes = attributes.iter();
    if attributes.len() == 0 {
        return Err(Error(String::from(
            "Need to specify at least one attribute",
        )));
    }

    if attributes.len() % 2 != 0 {
        return Err(Error(String::from(
            "Need to specify attributes and values in pairs",
        )));
    }

    let mut result = HashMap::new();
    while let (Some(k), Some(v)) = (attributes.next(), attributes.next()) {
        result.insert(k.to_owned(), v.to_owned());
    }
    match attributes.next() {
        None => Ok(result),
        Some(k) => Err(Error(String::from(&format!(
            "Key '{k}' is missing a value"
        )))),
    }
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

async fn lookup(attributes: &impl AsAttributes) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    if let Some(item) = items.first() {
        let bytes = item.secret().await?;
        let secret =
            std::str::from_utf8(&bytes).map_err(|_| Error::new("Secret is not valid utf-8"))?;
        println!("{secret}");
    }

    Ok(())
}

async fn search(attributes: &impl AsAttributes, all: bool) -> Result<(), Error> {
    let collection = collection().await?;
    let items = collection.search_items(attributes).await?;

    if all {
        for item in items {
            print_item(&item).await?;
        }
    } else if let Some(item) = items.first() {
        print_item(item).await?;
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

async fn print_item<'a>(item: &oo7::dbus::Item<'a>) -> Result<(), Error> {
    use std::fmt::Write;

    let label = item.label().await?;
    let bytes = item.secret().await?;
    // TODO Maybe show bytes in hex instead of failing?
    let secret =
        std::str::from_utf8(&bytes).map_err(|_| Error::new("Secret is not valid utf-8"))?;
    let mut attributes = item.attributes().await?;
    let created = item.created().await?;
    let modified = item.modified().await?;

    let created = chrono::DateTime::<chrono::Utc>::from_timestamp(created.as_secs() as i64, 0)
        .unwrap()
        .with_timezone(&chrono::Local);
    let modified = chrono::DateTime::<chrono::Utc>::from_timestamp(modified.as_secs() as i64, 0)
        .unwrap()
        .with_timezone(&chrono::Local);

    let mut result = format!("[{label}]\n");
    writeln!(&mut result, "secret = {secret}").unwrap();
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
