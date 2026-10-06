# PaperFlux Server

[Русский](README.md) · **English** · [Android client](https://github.com/Flofyyk/PaperFluxAndroid) · [Releases](https://github.com/Flofyyk/PaperFlux/releases/latest)

PaperFlux VPN tunnel server with Yandex Docs and Mail.ru Docs transports. Receives client traffic through a document channel and forwards it to the internet.

New changes are available in the [0.5.12-rc.1 public test release](https://github.com/Flofyyk/PaperFlux/releases/tag/v0.5.12-rc.1); it does not replace the stable release automatically. See the [public beta notes](docs/PUBLIC_BETA.md) for test scope, scaling limits and the unresolved Mail.ru throughput issue.

## Features

- Authenticated encrypted sessions with a separate access key for each profile.
- Two Yandex Docs channels and an optional Volga fallback channel.
- Automatic reconnection and DNS/TCP readiness checks.
- Bounded queues, traffic rate limits and active-flow limits.
- Exit readiness confirmation before data transmission and a 4096-packet replay window.
- Rootless IPv4 TCP/UDP forwarding in `proxy` mode and Linux packet forwarding in `raw` mode.
- Experimental grouped proxy for independent profiles sharing one process.

## How it works

```text
Android client ↔ document transport ↔ PaperFlux Server ↔ internet
```

The client and server join the same documents. Data is batched, compressed and carried through an encrypted session. The VPS reconstructs packets and handles outbound connections; replies follow the reverse path.

The main Yandex Docs transport uses collaboration cursor messages without writing traffic into document text. Volga uses text operations and requires a separate empty document with editing access.

If one document channel disconnects, the remaining channel continues carrying traffic while the disconnected channel recovers independently. Tunnel readiness requires document authorization, an authenticated session and successful DNS/TCP checks.

After a server restart, Session confirms the connection with a fresh challenge without waiting for the old session to time out. Stale confirmations cannot replace an established session.

## Deployment

Linux `amd64` and `arm64` binaries are available in [releases](https://github.com/Flofyyk/PaperFlux/releases/latest). Use `uname -m` to select an architecture: `x86_64` maps to `amd64`, and `aarch64` maps to `arm64`.

1. Install the binary on your VPS.
2. Prepare a document and profile settings: ID, access key and client virtual IP.
3. Run the server with `--session` and configure a systemd service.
4. Add the matching profile to the Android client.

Single-profile example:

```bash
./paperflux --exit-node --session --mode proxy \
  --transport yandex \
  --urls "https://disk.yandex.ru/i/DOCUMENT_ID" \
  --client-ip 10.10.10.2 \
  --profile-id 1 \
  --profile-token "REPLACE_WITH_RANDOM_PROFILE_KEY"
```

Replace the example document URL and key. Both endpoints must use matching IDs, keys, virtual IPs and transport settings.

The [deployment guide](docs/DEPLOYMENT.md) covers service users, systemd and upgrades. `raw` mode requires root and additional Linux configuration. IPv6 is not supported. Legacy PFS2 is not compatible with Session.

TCP recovery, buffers and proxy ingress queue settings are documented in the [transport guide](docs/TRANSPORTS.md#экспериментальный-tcp-recovery). DNS/TCP probes have a separate small connection pool that ordinary application traffic cannot occupy.

## Documentation

The following guides are in Russian:

- [Deployment](docs/DEPLOYMENT.md)
- [Transports and Yandex authorization](docs/TRANSPORTS.md)
- [Android client setup](docs/PAPERFLUX.md)
- [Profile discovery and sharing](docs/PROFILES.md)
- [Multiple users and backup servers](docs/MULTIUSER.md)
- [Experimental grouped proxy](docs/EXPERIMENTAL_GROUPS.md)
- [Legacy PFS2](docs/SECURITY_PFS2.md)

## Build

Go 1.26.4 or newer is required. On Linux:

```bash
git clone https://github.com/Flofyyk/PaperFlux.git
cd PaperFlux
go build -trimpath -o paperflux .
```

Use [build-android-native.ps1](scripts/build-android-native.ps1) with Android NDK to rebuild the Android core.

## Security

Session uses AES-256-GCM to encrypt the client-to-VPS connection. Protection beyond the VPS depends on application protocols such as HTTPS. The document service can observe exchange timing and volume. Profile configurations contain access keys and should only be shared with trusted recipients.

## License

[GPL-3.0-or-later](LICENSE). Third-party components are listed in [NOTICE](NOTICE). Based on [OpenFlux](https://github.com/p1neappleXpress/OpenFlux).

Provided as is, without warranties. Use on systems you own or are authorized to access.
