# PaperFlux Server

**English** | [Русский](README.ru.md)

PaperFlux Server is the Linux exit-node and transport core used by the PaperFlux Android client. It accepts framed traffic from a client, carries it through a user-provided Yandex Docs channel, and opens the destination connection from the VPS. The Android application is maintained separately in [PaperFlux Android](https://github.com/Flofyyk/PaperFluxAndroid).

This repository is a maintained fork of [p1neappleXpress/OpenFlux](https://github.com/p1neappleXpress/OpenFlux). PaperFlux adds the client-facing profile flow, bounded adaptive batching, session checks, and the deployment documentation below. It does not contain a user's document URL, token, or VPS credentials.

### Transport path

```text
Android TUN → PaperFlux native client → Yandex Docs Engine.IO/WebSocket
           → PaperFlux exit node → TCP destination
```

The Yandex adapter performs polling, upgrades to WebSocket, authorizes the Socket.IO session, and then transfers bounded adaptive batches. The wire format remains compatible with Base64/Socket.IO so an existing document can be used without a second relay protocol.

## Requirements
1. Golang v. 1.26.3+ - is required for building the desktop client / exit-node binary;
2. Android Native Development Kit (NDK) v.27.0.12077973+ - is required for building Android client binary;
3. XCode v. 26.6+ - is required for building iOS client binary;
4. Linux VPS / VDS exit node.

## Components

- `transport/yandex` — Yandex Docs polling, WebSocket upgrade, authorization, and framing;
- `tunnel` — virtual interface and packet forwarding;
- `socks5` — optional desktop SOCKS5 listener;
- `network` — packet parsing and checksums;
- `transport/oneme` — the optional MAX transport inherited from upstream.

## Structure

```
paperflux/
├── main.go
├── transport/
│   ├── transport.go      # Transport interface
│   └── yandex/           # Yandex Docs backend
│   └── oneme/            # MAX Messenger backend
├── tunnel/
│   ├── tunnel.go         # TCP tunnel core
│   ├── endpoint.go       # Virtual NIC
│   └── rawsocket.go      # Raw socket (exit node)
├── socks5/               # SOCKS5 server
├── network/              # Checksums, packet parsing
└── utils/                # Debug logging
```

## Build

```bash
go mod tidy
go build -o paperflux .
```

## Build for Android (client binary)
```bash
export ANDROID_NDK_HOME=<your Android NDK path>
./build_android.sh
```

## Build for iOS (client binary)
```bash
export XCODE_PATH="<your Xcode.app path>" # optional, defaults to /Applications/Xcode.app
./build_ios.sh
```

## Run an exit node

### 1. Setting up exit node
1. You must have root access on exit node machine;
2. Only legacy Yandex document editor is supported (you can toggle this setting from the interface).

Setup commands for exit node:
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./paperflux --exit-node --url "YOUR_YANDEX_DOC_URL" --debug
```

## Run a desktop client

Setup commands for desktop client:
```bash
./paperflux --client --url "YOUR_YANDEX_DOC_URL" --socks5 :1080 --debug
```

Then set up SOCKS5 proxy in your browser at localhost:1080.

## Flags

| Flag          | Default             | Description                |
|---------------|---------------------|----------------------------|
| `--client`    |                     | Run as client              |
| `--exit-node` |                     | Run as exit node           |
| `--socks5`    | `:1080`             | SOCKS5 listen address      |
| `--url`       | `https://localhost` | Document URL (Yandex Docs) |
| `--maxToken`  | ``                  | Auth token (Max)           |
| `--maxUid`    | ``                  | User ID (Max)              |
| `--debug`     | `false`             | Enable verbose logging     |
| `--transport` | `yandex`            | Select transport backend   |

## Implementing custom transports

You can implement the `Transport` interface in `transport/transport.go` and register a backend in the transport selector. Keep framing, authentication, and backpressure rules explicit when adding a new backend.

## License

This project is licensed under the **GNU General Public License v3.0 or later**.
See [LICENSE](LICENSE) for the full text.

Third-party licenses are listed in [NOTICE](NOTICE).

## Disclaimer

Educational use only. Test on your own machines and networks.

