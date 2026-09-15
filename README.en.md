# PaperFlux Server

[Русский](README.md) · **English** · [Android client](https://github.com/Flofyyk/PaperFluxAndroid)

PaperFlux is a TCP tunnel that carries data through Yandex Docs. The client accepts application traffic; a VPS exit node forwards it to the destination and sends responses back through the same channel.

Based on [OpenFlux](https://github.com/p1neappleXpress/OpenFlux), this repository contains the server and shared PaperFlux transport core.

## How it works

```text
Android apps ↔ VPN/TCP stack ↔ PFS2
                                 ↕
                  Yandex Docs collaboration channel
                                 ↕
                         VPS ↔ destination
```

The Android client processes VPN-interface packets through a local network stack. A SOCKS5 entry point is also available for desktop clients.

Both endpoints join the same Yandex document. The transport batches and encrypts data, then encodes it inside cursor messages sent through Socket.IO over Engine.IO/WebSocket. Packet content does not need to be written into the document text.

The VPS decodes these messages and forwards TCP packets using raw sockets. Responses follow the reverse path.

## Secure sessions and recovery

PFS2 authenticates peers using profile credentials, exchanges keys with X25519 and encrypts messages with AES-256-GCM. Application data is accepted only after session confirmation. Encryption covers the client-to-VPS path; protection beyond the VPS depends on the application's protocol, such as HTTPS.

The document service can observe message timing and sizes. See [PFS2](docs/SECURITY_PFS2.md) for details.

Connection readiness requires document authentication, a secure peer session and DNS/TCP verification. After a disconnect, the transport fetches document parameters again and creates a fresh WebSocket session. Retries use exponential delays with jitter; expired queued packets are discarded.

## Compatibility and documentation

The primary configuration is PaperFlux Android with a compatible PaperFlux server over Yandex Docs. The current path targets IPv4/TCP; general UDP and IPv6 support are not advertised.

- [Linux VPS deployment](docs/DEPLOYMENT.md) (Russian)
- [Android profiles and connection](docs/PAPERFLUX.md) (Russian)
- [PFS2 protocol](docs/SECURITY_PFS2.md) (Russian)

## License and use

[GPL-3.0-or-later](LICENSE); third-party notices are in [NOTICE](NOTICE).

For education and research on systems you own or are authorized to use. Provided as is, without warranties. Users are responsible for their deployments and use.
