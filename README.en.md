# PaperFlux Server

[Русский](README.md) | **English**

The server component of PaperFlux for a Linux server you administer. It accepts connections from compatible PaperFlux clients and forwards them through an exit node.

The Android client is maintained separately: [PaperFlux Android](https://github.com/Flofyyk/PaperFluxAndroid).

## Features

- Linux exit-node mode.
- Yandex Docs transport over WebSocket.
- Profile authentication and encrypted transport messages.
- Local SOCKS5 listener for desktop-client testing.
- Android support: TUN descriptor handoff, DNS/TCP checks, and traffic counters.

## Requirements

- A Linux server with root access for exit-node mode.
- Go 1.26.3 or later.
- Profile data and a document URL created for your deployment.

## Build

```bash
go mod tidy
go build -o paperflux .
```

## Run an exit node

```bash
sudo ./paperflux --exit-node --url "YOUR_DOCUMENT_URL"
```

## Local test

This starts the client and a SOCKS5 listener on `127.0.0.1:1080`:

```bash
./paperflux --client --url "YOUR_DOCUMENT_URL" --socks5 :1080
```

Run `./paperflux --help` for all available parameters.

## Documentation

- [Android client connection](docs/PAPERFLUX.md)
- [PFS2 details](docs/SECURITY_PFS2.md)
- [GPL-3.0-or-later license](LICENSE)

## Use

Use PaperFlux only for education, research, and testing on systems you own or are explicitly authorized to use. You are responsible for your server, access, data, and traffic.
