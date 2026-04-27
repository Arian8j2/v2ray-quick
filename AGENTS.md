# AGENTS.md

## Repo Shape
- Go module `v2ray-quick` targeting Go `1.24.7`; CLI entrypoint is `cmd/v2ray-quick/main.go`.
- Runtime code lives in `internal/quick`; VLESS URL parsing lives in `internal/link` and is the only package with tests currently.
- There is no CI config in this repo; trust `go.mod`, `Makefile`, and source over assumptions.

## Commands
- Full test suite: `make test` or `go test ./...`.
- Focus parser tests: `go test ./internal/link -run TestParseVLESS`.
- Build release-style local binary: `make build`; this sets `CGO_ENABLED=0`, defaults `GOOS=linux GOARCH=amd64`, uses tags `netgo,osusergo`, and writes `./v2ray-quick`.
- Cross-build by overriding Make vars, for example `make build GOOS=linux GOARCH=arm64`.

## CLI And Runtime Gotchas
- The tool's command shape and terminal output are based on the look and feel of `wg-quick`; preserve that style when changing UX.
- CLI form is `v2ray-quick up [-f] [-a address|--address address] ./name.conf` and `v2ray-quick down ./name.conf`.
- Config filenames must end in `.conf`; the tun interface name is the basename without `.conf` and must fit Linux's 15-byte interface-name limit.
- `.conf` files and the built `v2ray-quick` binary are ignored by git; avoid adding real proxy configs or generated binaries.
- Config loading reads the first nonblank line only and currently supports only `vless://` links.
- Supported VLESS options are intentionally narrow: encryption `none`, security `none` or `tls`, transport `tcp` or `ws`.
- `up` without `-f` detaches and sends stdio to `/dev/null`; use `up -f` when debugging startup or sing-box logs.
- Runtime is Linux/TUN oriented and may require root or `CAP_NET_ADMIN`; `down` shells out to `ip link delete dev <interface>`.
- The generated sing-box tun inbound has `AutoRoute: false`, so the tool creates the interface but does not install routes for the user.
