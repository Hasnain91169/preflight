# preflight

[![CI](https://github.com/Hasnain91169/preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/Hasnain91169/preflight/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A small Rust CLI that screens text **before** it is sent to an LLM:

- **Redacts PII** (emails, UK and Irish phone numbers, payment cards, IBANs, Irish PPS numbers, UK National Insurance numbers) and replaces each value with a stable token such as `[EMAIL_1]`.
- **Flags likely prompt injection** (instructions to ignore the system prompt, fake authority, hidden HTML comments, invisible characters, exfiltration and secrecy requests) and gives a 0 to 100 risk score.
- **Fails a pipeline** with exit code 2 when risk reaches a threshold, so risky documents can be routed to a human instead of an agent.

I built it as a learning project in Rust, aimed at a real problem from my AI automation work: inbound emails and documents go straight into LLM workflows, and they can carry both personal data and instructions aimed at the model.

## Example

```text
$ preflight examples/inbound_email.txt --summary-only --fail-on medium
Injection risk: High (score 100/100)
  - override_instructions (+40, line 12, x1): Asks the model to ignore or replace its instructions
  - data_exfiltration (+25, line 13, x1): Asks the model to send data to an external address
  - secrecy (+25, line 14, x1): Asks the model to hide its actions from the user
  - fake_authority (+20, line 12, x1): Claims to come from the system, an admin or the model vendor
  - hidden_html_comment (+15, line 12, x1): Contains an HTML comment, a common place to hide instructions
PII redacted:
  - EMAIL: 2 distinct, 2 total
  - IBAN: 1 distinct, 1 total
  - PPSN: 1 distinct, 1 total
  - PHONE: 2 distinct, 2 total
$ echo $?
2
```

The sample input is a fake supplier email asking to change bank details, with an instruction for an AI assistant hidden in an HTML comment.

## Usage

```bash
cargo build --release

# File or stdin
./target/release/preflight document.txt
cat document.txt | ./target/release/preflight

# JSON for a pipeline (redacted text plus findings; original PII values are never included)
./target/release/preflight document.txt --format json

# Gate a workflow: exit 2 on medium or high risk
./target/release/preflight document.txt --fail-on medium --summary-only
```

| Exit code | Meaning |
|---|---|
| 0 | Screened, below threshold |
| 1 | Error (unreadable file, empty input, invalid UTF-8) |
| 2 | Injection risk at or above `--fail-on` |

## How it works

```
input text ──┬──> inject::scan   (runs on the ORIGINAL text)
             └──> redact::redact (rules applied in order)
                         │
                         └──> Report { redacted_text, pii, injection } ──> text or JSON
```

Injection scanning runs on the original text because redaction would hide exfiltration targets such as `records@attacker.com`.

**Redaction.** Each rule is a regex plus an optional checksum validator, which keeps false positives down: a 16-digit number only counts as a card if it passes Luhn, an IBAN only if it passes ISO 13616 mod-97, and a PPSN only if its check letter is correct. Long digit patterns run before phone numbers so the phone rule cannot eat part of a card number. The same value always gets the same token, so the model can still tell that two mentions refer to one person.

**Injection scoring.** Each signal has a weight. A signal counts once however many times it appears, so one repeated phrase cannot max out the score; the total is capped at 100. Levels: 0 none, 1 to 29 low, 30 to 59 medium, 60+ high.

## Design notes

**Ownership and borrowing.** Public functions take `&str`, so the caller keeps ownership of the original document. Inside `redact`, the working text is a `Cow<str>`: it stays borrowed while no rule matches and only allocates a new `String` on the first replacement. `regex::replace_all` already returns a `Cow`, so unchanged passes cost nothing.

**Error handling.** One error enum (`PreflightError`, via `thiserror`) covers every failure. Library functions return `Result<T>` and use `?`; nothing in library code panics on user input. The only `expect` calls are on built-in regexes, which are fixed at compile time, so a failure there is a programming bug. `main` maps errors to exit code 1 and prints a readable message to stderr.

**Library and binary split.** `lib.rs` holds all the logic; `main.rs` only parses arguments, does I/O and picks the exit code. That keeps the logic unit-testable without spawning a process. Integration tests in `tests/cli.rs` run the real binary to check exit codes and output.

**Dependencies.** Five crates, each with one job: `clap` (argument parsing), `regex` (matching, linear-time so no catastrophic backtracking), `serde` and `serde_json` (JSON report), `thiserror` (error type). `Cargo.lock` is committed because this is a binary. Regexes compile once on first use through `std::sync::LazyLock`, so no extra crate is needed for lazy statics.

**Privacy by default.** The JSON report contains counts and tokens, never the original values, so it is safe to log.

## Limitations

- **This is a tripwire, not a security boundary.** Regex heuristics catch common, lazy attacks; a determined attacker can rephrase. Real protection still needs least-privilege tools for the agent, human approval for side effects, and treating retrieved content as data.
- PII coverage is UK and Ireland focused and regex based. It will miss names and free-text addresses, which need an NER model.
- English-language injection patterns only.

## Possible next steps

- Load extra rules from a TOML file
- Optional call to an LLM API (`reqwest`) after screening, so it works as a proxy
- Name detection via an NER model

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs all three on every push and pull request.

## License

MIT
