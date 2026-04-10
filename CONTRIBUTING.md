# Contributing to SanitAI

Thank you for your interest in contributing to SanitAI.

## Getting started

```sh
git clone https://github.com/sanitai/sanitai.git
cd sanitai
make install-hooks
cargo build --workspace
cargo test --workspace
```

Requires Rust 1.87+ (see `rust-toolchain.toml`).

## Development workflow

1. Create a branch from `main`.
2. Make your changes.
3. Run `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --workspace`.
4. Open a pull request against `main`.

The pre-push hook runs `sanitai scan` on changed files to catch accidental secret commits. Install hooks with `make install-hooks`.

## Integration tests

Integration tests require a compiled binary:

```sh
cargo build -p sanitai-cli
cargo test -p sanitai-cli --test integration -- --ignored
```

## Adding a detector

1. Add a new `Rule` entry in `crates/sanitai-detectors/src/regex_detector.rs`.
2. Add a corresponding fixture generator in `crates/sanitai-fixtures/src/lib.rs`.
3. Write unit tests covering true positives and false positives.

## Adding a parser

1. Create a new module under `crates/sanitai-parsers/src/`.
2. Implement the `Parser` trait from `sanitai-core`.
3. Wire it into the CLI's format sniffing logic in `crates/sanitai-cli/src/main.rs`.

## Security vulnerabilities

If you discover a security vulnerability, please follow the process in [SECURITY.md](SECURITY.md). Do not open a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
