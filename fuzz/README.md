# Fuzz targets

`cargo-fuzz` targets for the parsers that handle data this project does
not control.

## What is fuzzed, and why these

| Target | Parses | Why it matters |
| --- | --- | --- |
| `proc-net` | `/proc/net/{tcp,tcp6,udp,udp6}` text | The kernel's socket table, which reflects the result of connection attempts a remote peer can cause. The parser splits a whitespace-delimited table with hand-computed column offsets and decodes a hex address in the kernel's per-word little-endian encoding. |
| `nft-wire` | `NETLINK_NETFILTER` response bytes | A hand-rolled `nlmsghdr` frame decoder: message lengths, offsets, and nested nftables TLV attributes, all read out of the buffer by hand. The buffer comes from a netlink socket, so its contents are as far from trusted as a parser ever gets. |

The common shape of both is a decoder that walks a length-prefixed
structure. That is where out-of-bounds slices, integer overflows on
`offset + len`, and infinite loops on a zero-length element live.

## Running

The fuzz crate is deliberately **not** a workspace member. `cargo-fuzz`
requires a nightly toolchain (it builds the libFuzzer harness with
`-Z sanitizer=address`), and the workspace is pinned to stable 1.99.1 by
`rust-toolchain.toml`. Keeping `fuzz/` outside the workspace means
`cargo build --workspace` and `cargo test --workspace` never see it, so
the stable pin is untouched.

```bash
# One-time setup.
cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal

# Run a target until you stop it.
cargo +nightly fuzz run nft-wire fuzz/corpus/nft-wire fuzz/seeds/nft-wire

# Run it for a fixed budget instead.
cargo +nightly fuzz run nft-wire fuzz/corpus/nft-wire fuzz/seeds/nft-wire \
  -- -max_total_time=300

# Reproduce a saved crash.
cargo +nightly fuzz run nft-wire fuzz/artifacts/nft-wire/crash-<hash>

# Minimise a crash to the smallest input that still triggers it.
cargo +nightly fuzz tmin nft-wire fuzz/artifacts/nft-wire/crash-<hash>
```

## The corpus

Two directories, for two different reasons.

`seeds/<target>/` is **committed**. It holds the curated starting
points:

- the real `/proc/net` fixtures from
  `crates/anne-de-breuil/fixtures/proc_net/`, because a fuzzer starting
  from nothing spends most of its budget rediscovering the column
  layout of a `/proc/net/tcp` row;
- `nft-wire/empty_table_attr.bin`, the crash input that found the
  `decode_nla_string` bug described below.

`corpus/<target>/` is **gitignored**. It is the fuzzer's working corpus
-- libFuzzer writes every new interesting input there, and that churn
does not belong in the repository. libFuzzer reads seeds from every
directory it is given and writes to the first, so the working corpus
starts empty and the committed seeds still shape the run.

The directory has to exist before libFuzzer will start, so create it
first:

```bash
mkdir -p fuzz/corpus/nft-wire
```

CI does the same thing before each run.

## What a failure means

Both targets assert on the *result*, not just on the absence of a
panic. A target fails when the parser produces something the caller
could not act on correctly: an endpoint with an impossible port, a chain
whose name or table is present but empty, a buffer that reports both
"finished" and "failed".

That distinction has already paid for itself. The `nft-wire` target
found that `decode_nla_string` decoded a zero-length NLA string
attribute as `Some("")` rather than `None`. The consumer
(`nft_chain_to_raw_rule`) substitutes `"?"` for an unknown table or
chain name, but it does so on `None` only -- so an empty attribute
produced a rule id of `nftables//input`, a rule that named no table at
all. The fix and its regression test are in
`crates/anne-de-breuil/src/adapters/linux_collector/nft_wire.rs`.

## In CI

`ci.yml` has a `fuzz` job that builds every target and smoke-runs each
for 60 seconds, seeded from `seeds/` and writing to the gitignored
working corpus. That is enough to catch a target that stops compiling
or starts tripping an assertion, without making a pull request wait on a
long fuzzing campaign.
