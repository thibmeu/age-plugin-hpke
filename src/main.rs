mod cli;

pub const PLUGIN_NAME: &str = "hpke";

pub fn run_state_machine(state_machine: String) {
    println!("Running state machine: {}", state_machine);
}

fn main() {
    let cli = cli::build();
    if let Some(state_machine) = cli.age_plugin {
        return run_state_machine(state_machine);
    }

    println!("Hello, world!");
}
