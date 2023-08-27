use age_plugin_hpke::{new_identity, new_identity_to_string};
use cli::{Aead, Kem};

mod cli;

pub const PLUGIN_NAME: &str = "hpke";

pub fn generate(associated_data: &str, kem: Kem, aead: Aead) {
    let (identity, recipient) = new_identity(kem.to_alg(), aead.to_alg(), associated_data);
    println!(
        "{}",
        new_identity_to_string(PLUGIN_NAME, &identity, &recipient)
    );
}

pub fn run_state_machine(state_machine: String) {
    age_plugin_hpke::run_state_machine(PLUGIN_NAME, &state_machine).unwrap()
}

fn main() {
    let cli = cli::build();

    if let Some(state_machine) = cli.age_plugin {
        return run_state_machine(state_machine);
    }

    if let Some(args) = cli.generate {
        if args.generate {
            generate(
                &args.associated_data.unwrap(),
                args.kem.unwrap(),
                args.aead.unwrap(),
            )
        }
    }
}
