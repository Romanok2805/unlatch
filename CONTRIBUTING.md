# Contributing

Read [the architecture](docs/architecture.md) first. It explains the rules the code follows and why.

## Checks

Run these before opening a pull request. CI runs the same ones and fails on any warning.

```sh
cargo fmt --check
cargo clippy --all-targets --locked
cargo test --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --locked
cargo deny check
```

The lints in `Cargo.toml` are strict on purpose; the comments there explain them.

## Fuzzing

The code that reads untrusted input has fuzz targets in `fuzz/`, which CI runs for a minute each.
To run one for longer, with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cd fuzz
cargo +nightly fuzz run jws
```

`cargo fuzz list` names the targets. On Windows, the folder of Visual Studio's
`clang_rt.asan_dynamic-x86_64.dll` must be on `PATH`. An input that breaks a target is saved in
`fuzz/artifacts/`; add it as a test of the code it broke.

## Conformance

[conformance/](conformance/README.md) describes testing against the OpenID Foundation's suite.

## Adding a dependency

Say in the pull request what the crate does for us, why writing it ourselves would be worse, who
maintains it and which of its features we enable. Allowed licenses and sources are in `deny.toml`.

## Comments and documentation

Comments explain why the code is the way it is. Documentation states each fact in one place and
links to it everywhere else.
