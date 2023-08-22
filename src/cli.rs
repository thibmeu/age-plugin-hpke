use age_plugin_hpke::agile::{AeadAlg, KemAlg};
use clap::{Args, Parser, ValueEnum};

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
    #[arg(long, hide = true, group = "action")]
    pub age_plugin: Option<String>,
    #[command(flatten)]
    pub generate: Option<GenerateArg>,
}

#[derive(Args)]
pub struct GenerateArg {
    #[arg(long, default_value_t = false, group = "action")]
    pub generate: bool,
    #[arg(long, requires = "action")]
    pub associated_data: Option<String>,
    #[arg(long, requires = "action")]
    pub kem: Option<Kem>,
    #[arg(long, requires = "action")]
    pub aead: Option<Aead>,
}

#[derive(Clone, ValueEnum)]
pub enum Kem {
    X25519HkdfSha256,
    X25519Kyber768Draft00,
    P256HkdfSha256,
    P521HkdfSha512,
}

impl Kem {
    pub fn to_alg(&self) -> KemAlg {
        match self {
            Self::X25519HkdfSha256 => KemAlg::X25519HkdfSha256,
            Self::X25519Kyber768Draft00 => KemAlg::X25519Kyber768Draft00,
            Self::P256HkdfSha256 => KemAlg::DhP256HkdfSha256,
            Self::P521HkdfSha512 => KemAlg::DhP521HkdfSha512,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum Aead {
    AesGcm128,
    AesGcm256,
    ChaCha20Poly1305,
}

impl Aead {
    pub fn to_alg(&self) -> AeadAlg {
        match self {
            Self::AesGcm128 => AeadAlg::AesGcm128,
            Self::AesGcm256 => AeadAlg::AesGcm256,
            Self::ChaCha20Poly1305 => AeadAlg::ChaCha20Poly1305,
        }
    }
}

#[allow(dead_code)]
pub fn build() -> Cli {
    Cli::parse()
}
