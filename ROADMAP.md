# Roadmap

Things under consideration for this crate, none of them committed. Each entry
says what would change and what has to be true first.

## Fold flexaccess-keys into this repository as a subcrate

Today [flexaccess-keys] is its own repository, consumed here by git tag and
re-exported as `flexaccess_keys`; every product pins both tags and has to keep
them in step (this crate signs and verifies with exactly the version it
re-exports). The idea is to make this repository a Cargo workspace with
`flexaccess-keys` as a member crate next to `flexaccess-iroh`, so the key
format and the transcript over it are versioned, tagged, tested, and reviewed
together, and a product pins one tag for both.

What would change:

- A workspace root with two members; `flexaccess-iroh` depends on
  `flexaccess-keys` by `path`. Consumers keep depending on each crate by git
  tag (`package = "flexaccess-keys"` from the same repository), so the
  `flexaccess-keys` CLI, the iOS/FFI consumers, and anything that wants the
  key format without iroh keep working without pulling iroh in.
- One release workflow tagging the repository once; both crates carry the same
  version.
- The e2e harness's `keygen` and the `flexaccess-keys` CLI would share the
  same code path directly rather than via the re-export.

What has to be settled first:

- Whether every consumer of `flexaccess-keys` is happy to take it from this
  repository's tags, or whether the standalone repository must live on (in
  which case a subcrate here only creates a second source of truth and the
  idea should be dropped).
- The CI and release workflows here assume a single package
  (`cargo metadata … .packages[0]`, the minimum-iroh job's `cargo update -p
  iroh`); they need to become workspace-aware.
- Whether `flexaccess-keys`' own release binaries (the CLI downloaded by
  product e2e scripts) keep being published, and from which repository.

Not started; nothing in this repository is arranged around it yet.

[flexaccess-keys]: https://github.com/flexaccessdev/flexaccess-keys
