use std::io::{self};

use agile::{agile_gen_keypair, AeadAlg, KemAlg};

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

pub fn print_new_identity(plugin_name: &str, identity: Vec<u8>, recipient: Vec<u8>) {
    age_plugin::print_new_identity(plugin_name, &identity, &recipient)
}
