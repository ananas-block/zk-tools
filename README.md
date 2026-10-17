# zk-tools

The Zolana local provers: the Go bridges that `zolana-web-sdk` and `zolana-mobile-sdk` build their in-browser and on-device Groth16 proving from.

## Layout

- `prover-wasm/` (module `github.com/helius-labs/zk-tools`): the js/wasm bridge with its Arkworks kernel adapter, built by the web SDK. `testdata/transfer-2x2.json` is the demo request.
- `cgo/` (module `github.com/zkmopro/rust-gnark`): the c-archive bridge the mobile SDK's `rust-gnark` crate compiles.

Both require `github.com/helius-labs/zolana/prover/server`, the upstream prover, at a commit pinned in their `go.mod`; `go.sum` checks it. They currently pin helius-labs/zolana#420, which gives that module a fetchable path, and move to `main` once it merges.

## Notes

- Repeat upstream's `replace github.com/reilabs/gnark-lean-extractor/v3 => github.com/Lightprotocol/gnark-lean-extractor/v3 v3.0.0-20250920122823-aa0219463107`: Go applies only the main module's replacements.
- `go mod tidy` cannot complete: upstream's `prover/backend` has a file behind the `aeglos` build tag that imports the private `github.com/helius-labs/aeglos`. Builds and tests are unaffected; edit `go.mod` with `go get <module>@<commit>` instead.

## Validation

```sh
go vet ./... && go test ./...
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -o /tmp/zolana-prover.wasm ./prover-wasm
(cd cgo && go test ./... && go build -buildmode=c-archive -o /tmp/libgnark.a .)
```

`prover-wasm`'s proof test needs the staged 2x2 key from the web SDK layout and skips otherwise; the web and mobile SDKs run the proving gates against their staged keys.

## Rust CPU engine

[`rust/cpu-prover/`](rust/cpu-prover/README.md) contains the reusable Rust BN254 Groth16 CPU engine, including portable WASM SIMD, native/property tests, proof-blinding security gates and standalone WASM checks. It is consumed directly as a Cargo dependency; the existing Go bridges are unchanged.
