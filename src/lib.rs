use std::io::{self};

use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha384, kem::X25519HkdfSha256, Kem as KemTrait};

use internal::{Identity, Recipient};
use rand::{rngs::StdRng, SeedableRng};

use crate::internal::{IdentityPlugin, RecipientPlugin};

mod internal;

// These are the only algorithms we're gonna use for this example
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

pub fn run_state_machine(state_machine: &str) -> io::Result<()> {
    age_plugin::run_state_machine(state_machine, RecipientPlugin::new, IdentityPlugin::new)
}

pub fn new_identity(associated_data: &str) -> (Vec<u8>, Vec<u8>) {
    let mut csprng = StdRng::from_entropy();
    let (sk, pk) = Kem::gen_keypair(&mut csprng);
    let identity = Identity::new(&sk);
    let recipient = Recipient::new(&pk, associated_data.as_bytes());

    (identity.to_bytes(), recipient.to_bytes())
}

pub fn print_new_identity(plugin_name: &str, identity: Vec<u8>, recipient: Vec<u8>) {
    age_plugin::print_new_identity(plugin_name, &identity, &recipient)
}
