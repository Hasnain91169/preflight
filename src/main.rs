use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use preflight::{read_input, screen, RiskLevel};

/// Screen text before it reaches an LLM: redact PII and flag likely
/// prompt injection.
///
/// Exit codes: 0 = ok, 1 = error, 2 = injection risk at or above --fail-on.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// File to screen. Reads stdin if omitted or "-".
    file: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit with code 2 when injection risk reaches this level.
    #[arg(long, value_enum)]
    fail_on: Option<Threshold>,

    /// Text format only: print the summary without the redacted text.
    #[arg(long)]
    summary_only: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Threshold {
    Low,
    Medium,
    High,
}

impl From<Threshold> for RiskLevel {
    fn from(t: Threshold) -> Self {
        match t {
            Threshold::Low => RiskLevel::Low,
            Threshold::Medium => RiskLevel::Medium,
            Threshold::High => RiskLevel::High,
        }
    }
}

fn run(cli: &Cli) -> preflight::Result<bool> {
    let input = read_input(cli.file.as_deref())?;
    let report = screen(&input);

    match cli.format {
        Format::Json => println!("{}", report.to_json()?),
        Format::Text => print!("{}", report.to_text(!cli.summary_only)),
    }

    let tripped = cli
        .fail_on
        .is_some_and(|t| report.injection.level >= RiskLevel::from(t));
    Ok(tripped)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(2),
        Err(e) => {
            eprintln!("preflight: {e}");
            ExitCode::FAILURE
        }
    }
}
