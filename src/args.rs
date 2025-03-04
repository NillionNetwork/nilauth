use clap::Parser;

/// Nillion authority service.
#[derive(Parser)]
pub struct Cli {
    /// The path to the config file.
    #[clap(short, long)]
    pub config_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
