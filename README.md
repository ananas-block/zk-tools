# zk-tools

The Zolana local provers: the Go bridges that `zolana-web-sdk` and `zolana-mobile-sdk` build their in-browser and on-device Groth16 proving from, and the one vendored copy of the upstream prover code they share.

## Layout

- `/`: the module `zolana/prover`, the packages of `helius-labs/zolana`'s `prover/server` that the bridges and their tests import, byte for byte at the revision `upstream.lock.json` pins, plus:
  - `prover-wasm/`: the js/wasm bridge with its Arkworks kernel adapter, built by the web SDK.
  - `test-vectors/`: upstream's cross-language vectors, and `prover-wasm/testdata/transfer-2x2.json`, the demo request `web_fixture_test.go` generates.
- `cgo/`: the c-archive bridge module the mobile SDK's `rust-gnark` crate compiles, replacing `zolana/prover` with `../`.

## Consuming

The root module keeps upstream's path, so a consumer pins it the way it would a fork:

```
require zolana/prover v0.0.0
replace zolana/prover => github.com/helius-labs/zk-tools v0.1.0
replace github.com/reilabs/gnark-lean-extractor/v3 => github.com/Lightprotocol/gnark-lean-extractor/v3 v3.0.0-20250920122823-aa0219463107
```

The second `replace` is upstream's and has to be repeated: Go applies only the main module's replacements.

## Upstream

`upstream.lock.json` pins the `helius-labs/zolana` tag and commit. `scripts/check-upstream.sh` (CI job `upstream`) re-reads that commit and fails when a vendored file differs, an upstream file of a vendored package is missing, a vector differs, or either module's Go or gnark version does. The local edits it allows for:

- `common.FromHex` returns a fixed error that does not echo its input (`marshal_local_test.go`).
- Tests read the vectors from `test-vectors/` instead of the upstream root and `sdk-libs/fixtures`.
- `circuits/spp_transaction/shared/web_fixture_test.go` writes the demo request: `WEB_FIXTURE=$PWD/prover-wasm/testdata/transfer-2x2.json go test ./circuits/spp_transaction/shared -run TestWriteWebFixture`.

To move to a new upstream revision, copy the packages listed above from `prover/server`, re-apply those edits, regenerate the demo request, update `upstream.lock.json`, and run the gate.

## Validation

```sh
go test ./...
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -o /tmp/zolana-prover.wasm ./prover-wasm
(cd cgo && go test ./... && go build -buildmode=c-archive -o /tmp/libgnark.a .)
bash scripts/check-upstream.sh
```

`prover-wasm`'s proof test needs the 2x2 key at `examples/browser/public/keys/transfer_confidential_2_3.key` relative to the web SDK layout and skips otherwise; the web and mobile SDKs run the proving gates against the staged key.
