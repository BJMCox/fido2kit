# Contributing

## Build and test

You need Rust 1.89 or later from [rustup](https://rustup.rs). On macOS you also need the Xcode Command Line Tools (`xcode-select --install`), and on Linux `libudev-dev` for hidapi. The workspace has two crates: the portable `fido2kit`, whose `vault` module sits behind a default feature, and the macOS-only `fido2kit-mac`.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p fido2kit --no-default-features --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p fido2kit --no-default-features --locked
```

The `--no-default-features` lines check the build without the vault, which some apps use. CI runs all five.

## Run CodeQL locally

Run the same analysis as the `codeql` workflow before each push, with the shared config in `.github/codeql` and the `security-extended` suite. It needs the full CodeQL bundle, the CLI with every query pack, with `codeql` on the `PATH`:

```sh
gh release download codeql-bundle-v2.27.1 -R github/codeql-action -p 'codeql-bundle-osx64.tar.zst*'
shasum -a 256 -c codeql-bundle-osx64.tar.zst.checksum.txt
mkdir -p ~/.codeql/bundle && tar -xf codeql-bundle-osx64.tar.zst -C ~/.codeql/bundle
ln -s ~/.codeql/bundle/codeql/codeql ~/.local/bin/codeql
```

Then, from the repository root:

```sh
out=~/Library/Caches/fido2kit/codeql
mkdir -p "$out"
for language in rust actions; do
  codeql database create --overwrite --build-mode=none --language=$language \
    --codescanning-config=.github/codeql/codeql-config.yml --source-root=. "$out/$language"
  codeql database analyze --format=csv --output="$out/$language.csv" "$out/$language" \
    codeql/$language-queries:codeql-suites/$language-security-extended.qls
done
cat "$out"/*.csv
```

Empty CSV files mean no findings. The databases stay outside the source tree, so extraction never reads them. Tests live in `tests.rs` files, which the config excludes because CodeQL does not recognize `#[cfg(test)]`.

## Advisories

The `audit` job in CI runs `cargo audit` on the kit's own `Cargo.lock` only. An app resolves its own lock, so run `cargo audit` in each app before its release.

## Using the kit in an app

An app depends on the kit through `git` and `rev`, with the full commit SHA and the tag in a comment:

```toml
fido2kit = { git = "https://github.com/<owner>/fido2kit.git", rev = "<full commit SHA>" } # v0.1.0
```

A kit change reaches an app only through a new kit tag and a bump of `rev` in each app.
