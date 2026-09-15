# PaperFlux Server

[Русский](README.md) | **English**

PaperFlux Server is the server component of PaperFlux for a Linux VPS you administer. The exit node accepts connections from compatible clients and forwards traffic to the network.

Android client: [PaperFlux Android](https://github.com/Flofyyk/PaperFluxAndroid).

## Included components

- Linux exit node.
- Yandex Docs transport over WebSocket.
- Profile authentication and encrypted transport messages.
- Android client support: TUN handoff, DNS/TCP checks, and traffic counters.

## Deploy on a VPS

The full deployment guide, including systemd configuration and updates, is maintained in the [Russian README](README.md). It uses these steps:

1. Install Go 1.26.4 or later and build the binary.
2. Store the document URL and profile credentials in a root-only environment file.
3. Run the exit node as a systemd service.
4. Verify it through `systemctl status paperflux` and `journalctl -u paperflux -f`.

The current exit-node implementation requires root access for raw sockets.

## Main parameters

- `--exit-node` runs the VPS as an exit node.
- `--url` sets the Yandex Docs URL.
- `--profile-id` and `--profile-token` set profile credentials.
- `--transport yandex` selects the default transport.

Run `paperflux --help` for all options.

## Documentation

- [Android client connection](docs/PAPERFLUX.md)
- [PFS2 details](docs/SECURITY_PFS2.md)
- [GPL-3.0-or-later license](LICENSE)

## Use

Use PaperFlux only for education, research, and testing on systems you own or are explicitly authorized to use. You are responsible for your server, access, data, and traffic.
