use clap::Parser;

/// Plugin for age to interact with Hybrid Public Key Encryption (HPKE)
///
/// Example:
///     $ age-plugin-hpke --generate > my_id.key
///     $ cat my_id.key | grep 'recipient' | sed 's/.*\(age1.*\)/\1/' > my_id.key.pub
///     $ tar cvz ~/data | age -R my_id.key.pub > data.tar.gz.age
///     $ age --decrypt -i my_id.key -o data.tar.gz data.tar.gz.age
#[derive(Parser)]
#[command(author, version, about, verbatim_doc_comment)]
#[command(propagate_version = true)]
pub struct Cli {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,
    #[arg(long, hide = true)]
    pub age_plugin: Option<String>,
    #[arg(long, default_value_t = false)]
    pub generate: bool,
}

#[allow(dead_code)]
pub fn build() -> Cli {
    Cli::parse()
}
