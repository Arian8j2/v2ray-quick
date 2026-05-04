# v2ray-quick

`v2ray-quick` is a small Linux CLI for bringing up and tearing down an Xray TUN interface from a VLESS link. Its command shape and terminal output are intentionally modeled after `wg-quick`.

This project is entirely AI-written.

## Usage

Put a VLESS URL on the first nonblank line of a `.conf` file:

```text
vless://uuid@example.com:443?encryption=none&security=tls&type=ws&path=%2F&host=example.com#name
```

Bring the interface up:

```sh
sudo ./v2ray-quick up ./name.conf
```

Run in the foreground to see startup and Xray logs:

```sh
sudo ./v2ray-quick up -f ./name.conf
```

Tear the interface down:

```sh
sudo ./v2ray-quick down ./name.conf
```

The interface name is the config filename without `.conf`, so `name.conf` creates `name`. Linux interface names must be at most 15 bytes.

## Supported Config

- Only `vless://` links are supported for now.
- Supported stream transports are `tcp` and `ws`.

The generated Xray TUN inbound does not install routes; `v2ray-quick` creates the interface and assigns its address, but you must handle routes yourself.

## Build And Test

Run tests:

```sh
make test
```

Build a local Linux amd64 binary at `./v2ray-quick`:

```sh
make build
```
