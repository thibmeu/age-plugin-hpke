use std::io::{self};

use agile::{agile_gen_keypair, AeadAlg, KemAlg};

use bech32::{ToBase32, Variant};
use internal::{Identity, Recipient};
use rand::{rngs::StdRng, SeedableRng};

use crate::internal::{IdentityPlugin, RecipientPlugin};

pub mod agile;
mod internal;

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";
const PLUGIN_IDENTITY_PREFIX: &str = "age-plugin-";

pub fn run_state_machine(plugin_name: &str, state_machine: &str) -> io::Result<()> {
    age_plugin::run_state_machine(
        state_machine,
        || RecipientPlugin::new(plugin_name),
        || IdentityPlugin::new(plugin_name),
    )
}

pub fn new_identity(kem: KemAlg, aead: AeadAlg, associated_data: &str) -> (Vec<u8>, Vec<u8>) {
    let mut csprng = StdRng::from_entropy();
    let keypair = agile_gen_keypair(kem.clone(), &mut csprng);
    let identity = Identity::new(
        kem.clone(),
        aead.clone(),
        kem.kdf_alg(),
        keypair.private_key(),
        associated_data.as_bytes(),
    );
    let recipient = Recipient::new(
        kem.clone(),
        aead,
        kem.kdf_alg(),
        keypair.public_key(),
        associated_data.as_bytes(),
    );

    (identity.to_bytes(), recipient.to_bytes())
}

pub fn new_identity_to_string(plugin_name: &str, identity: &[u8], recipient: &[u8]) -> String {
    format!(
        "# created: {}
# recipient: {}
{}",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        recipient_to_string(plugin_name, recipient),
        identity_to_string(plugin_name, identity),
    )
}

pub fn identity_to_string(plugin_name: &str, identity: &[u8]) -> String {
    bech32::encode(
        &format!("{}{}-", PLUGIN_IDENTITY_PREFIX, plugin_name),
        identity.to_base32(),
        Variant::Bech32,
    )
    .expect("HRP is valid")
    .to_uppercase()
}

pub fn identity_from_string(identity: &str) -> Vec<u8> {
    use bech32::FromBase32;

    let mut identity = identity.trim_start();
    while identity.starts_with('#') {
        identity = identity
            .find('\n')
            .map(|i| identity.split_at(i + 1))
            .map(|(_, rest)| rest)
            .unwrap_or("")
            .trim_start();
    }
    let (_, identity_decoded, _) = bech32::decode(identity).unwrap();
    Vec::from_base32(&identity_decoded).unwrap()
}

pub fn recipient_to_string(plugin_name: &str, recipient: &[u8]) -> String {
    bech32::encode(
        &format!("{}{}", PLUGIN_RECIPIENT_PREFIX, plugin_name),
        recipient.to_base32(),
        Variant::Bech32,
    )
    .expect("HRP is valid")
}

pub fn convert_identity_to_recipient(identity: &[u8]) -> Vec<u8> {
    let recipient: Recipient = Identity::from_bytes(identity).into();
    recipient.to_bytes()
}
