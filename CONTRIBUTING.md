# Contributing

Read [the architecture](docs/architecture.md) first. It explains the rules the code follows and why.

## Checks

Run these before opening a pull request. CI runs the same ones and fails on any warning.

```sh
cargo fmt --check
cargo clippy --all-targets --locked
cargo test --locked
cargo deny check
```

The lints in `Cargo.toml` are strict on purpose; the comments there explain them.

## Adding a dependency

Say in the pull request what the crate does for us, why writing it ourselves would be worse, who
maintains it and which of its features we enable. Allowed licenses and sources are in `deny.toml`.

## Comments and documentation

Comments explain why the code is the way it is. Documentation states each fact in one place and
links to it everywhere else.
