use std::io::{self};

use agile::{agile_gen_keypair, AeadAlg, KemAlg};

use bech32::{ToBase32, Variant};
use internal::{Identity, Recipient};
use rand::{rngs::StdRng, SeedableRng};

use crate::internal::{IdentityPlugin, RecipientPlugin};

pub mod agile;
mod internal;

pub fn run_state_machine(state_machine: &str) -> io::Result<()> {
    age_plugin::run_state_machine(state_machine, RecipientPlugin::new, IdentityPlugin::new)
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

pub fn print_new_identity(plugin_name: &str, identity: &[u8], recipient: &[u8]) {
    age_plugin::print_new_identity(plugin_name, identity, recipient)
}

pub fn print_recipient(plugin_name: &str, identity: &[u8]) {
    const PLUGIN_RECIPIENT_PREFIX: &str = "age1";
    let recipient: Recipient = Identity::from_bytes(identity).into();
    let recipient = recipient.to_bytes();
    println!(
        "{}",
        bech32::encode(
            &format!("{}{}", PLUGIN_RECIPIENT_PREFIX, plugin_name),
            recipient.to_base32(),
            Variant::Bech32
        )
        .expect("HRP is valid")
    );
}
