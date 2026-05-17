# AGENTS.md

## Repo Shape
- Go module `v2ray-quick` targeting Go `1.25.6`; CLI entrypoint is `cmd/v2ray-quick/main.go`.
- Runtime code lives in `internal/quick`; VLESS URL parsing lives in `internal/link`; both packages have tests.
- There is no CI config in this repo; trust `go.mod`, `Makefile`, and source over assumptions.

## Commands
- Full test suite: `make test` or `go test ./...`.
- Focus parser tests: `go test ./internal/link -run TestParseVLESS`.
- Build release-style local binary: `make build`; this sets `CGO_ENABLED=0`, defaults `GOOS=linux GOARCH=amd64`, uses tags `netgo,osusergo`, and writes `./v2ray-quick`.
- Cross-build by overriding Make vars, for example `make build GOOS=linux GOARCH=arm64`.

## CLI And Runtime Gotchas
- The tool's command shape and terminal output are based on the look and feel of `wg-quick`; preserve that style when changing UX.
- CLI form is `v2ray-quick up [-f] [-a address|--address address] ./name.conf` and `v2ray-quick down ./name.conf`.
- The tun interface name is the basename up to the first dot (or the whole basename if no dot) and must fit Linux's 15-byte interface-name limit.
- `.conf` files and the built `v2ray-quick` binary are ignored by git; avoid adding real proxy configs or generated binaries.
- Config loading reads the first nonblank line only and currently supports only `vless://` links.
- Supported VLESS encryption is `none`; supported security is `none`, `tls`, or `reality`; supported transports are `tcp` and `ws`.
- The parser follows common v2rayNG/Xray share-link query fields for supported transports, including `flow`, `sni`, `fp`, `alpn`, `ech`, `pcs`, `pbk`, `sid`, `spx`, `pqv`, `headerType`, `host`, and `path`.
- `up` without `-f` detaches and sends stdio to `/dev/null`; use `up -f` when debugging startup or Xray logs.
- Runtime is Linux/TUN oriented and may require root or `CAP_NET_ADMIN`; `down` shells out to `ip link delete dev <interface>`.
- The generated Xray TUN inbound does not install routes; the tool creates the interface and assigns its address, but routes remain the user's responsibility.
