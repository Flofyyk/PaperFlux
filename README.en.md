# PaperFlux Server

[Русский](README.md) · **English** · [Android client](https://github.com/Flofyyk/PaperFluxAndroid)

PaperFlux is a TCP tunnel that carries data through Yandex Docs. The client accepts application traffic; a VPS exit node forwards it to the destination and sends responses back through the same channel.

Based on [OpenFlux](https://github.com/p1neappleXpress/OpenFlux), this repository contains the server and shared PaperFlux transport core.

## How it works

```text
Android apps ↔ VPN/TCP stack ↔ Session / legacy PFS2
                                 ↕
                  Yandex Docs collaboration channel
                                 ↕
                         VPS ↔ destination
```

The Android client processes VPN-interface packets through a local network stack. A SOCKS5 entry point is also available for desktop clients.

Both endpoints join the same Yandex document. The transport batches and encrypts data, then encodes it inside cursor messages sent through Socket.IO over Engine.IO/WebSocket. Packet content does not need to be written into the document text.

The VPS decodes these messages and forwards TCP traffic. The `proxy` mode uses ordinary outbound sockets without root; `raw` retains packet forwarding with Linux-specific setup. Responses follow the reverse path.

## Secure sessions and recovery

The current Session authenticates peers with profile credentials, negotiates capabilities and encrypts messages with directional AES-256-GCM. Legacy PFS2 with X25519 remains a separate compatibility mode. Application data is accepted only after session confirmation. Encryption covers the client-to-VPS path; protection beyond the VPS depends on the application's protocol, such as HTTPS.

The document service can observe message timing and sizes. See [PFS2](docs/SECURITY_PFS2.md) for details.

Connection readiness requires document authentication, a secure peer session and DNS/TCP verification. After a disconnect, the transport fetches document parameters again and creates a fresh WebSocket session. Retries use exponential delays with jitter; expired queued packets are discarded.

Session supports one or two Yandex documents. TCP flows use available document lanes; losing one lane does not require replacing the entire VPN. Restarted exit nodes are rediscovered using a fresh challenge before peer replacement. Restored lanes trigger immediate Android DNS/TCP verification. Collaborative editor authentication locks are completed without changing document content.

## Compatibility and documentation

The primary configuration is PaperFlux Android with a compatible PaperFlux server over Yandex Docs. Proxy mode forwards IPv4 TCP and UDP through ordinary outbound sockets. IPv6 is not supported.

Server 0.5.6–0.5.8 and Android 0.4.14–0.4.16 use compatible Session protocols and require `--session` on the server. Legacy PFS2 clients are not compatible with Session. Address-and-key setup requires the optional profile discovery service; complete profile import does not. Volga requires an empty document because it modifies its content. An optional encrypted verification-only channel helps with server-side Yandex CAPTCHA without carrying normal VPN traffic.

In 0.5.8, the grouped proxy resets its network stack and closes old TCP/UDP flows when the authenticated client session changes. Late packets and replies from the previous session are rejected. Ordinary document rotation retains active flows. The Session wire format is unchanged.

Linux `amd64` and `arm64` binaries are available in the [latest release](https://github.com/Flofyyk/PaperFlux/releases/latest). `uname -m` reports `x86_64` for amd64 and `aarch64` for arm64.

- [Linux VPS deployment](docs/DEPLOYMENT.md) (Russian)
- [Android profiles and connection](docs/PAPERFLUX.md) (Russian)
- [Profile discovery and sharing](docs/PROFILES.md) (Russian) — optional encrypted setup by server address and access key, independent of any bot or VPS provider.
- [PFS2 protocol](docs/SECURITY_PFS2.md) (Russian)
- [Transports and Yandex verification](docs/TRANSPORTS.md) (Russian)
- [Experimental grouped proxy](docs/EXPERIMENTAL_GROUPS.md) (Russian) — bounded shared processes; not a claim of production capacity.

## License and use

[GPL-3.0-or-later](LICENSE); third-party notices are in [NOTICE](NOTICE).

For education and research on systems you own or are authorized to use. Provided as is, without warranties. Users are responsible for their deployments and use.
