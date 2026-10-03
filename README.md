# dumbvpn2

Zero-Config Mesh-Proxy platform with Chrome JA4 mimicry, WireGuard-like Cryptokey overlay, zero-copy Linux splice(2), zero-latency Fake-IP DNS, and seamless Android native hot-reload.

## Features

- **Protocol**: MMX framing over WebSocket (RFC 6455 / RFC 8441) with 8-byte zero-copy header.
- **Chrome Mimicry**: 6-connection pool mitigating TCP Head-of-Line blocking.
- **E2E Cryptokey Routing**: X25519 & ChaCha20-Poly1305 over virtual `10.88.0.0/16`.
- **LAN Direct Fast-Path**: mDNS/UDP beacon discovery for direct Gigabit links.
- **Zero-Latency DNS**: Instant `198.18.0.0/15` synthetic responses with Radix Trie.
- **Zero-Copy Streaming**: Linux `splice(2)` pipe-based transfers in kernel space.
- **Dynamic Native Reload**: Seamless Android `.so` update via SCM_RIGHTS fd passing without APK reinstallation.
- **Infrastructure**: Envoy Proxy + rqlite distributed Raft consensus + automated Ansible deployment.

## Build Commands

~~~bash
just build-ui
just build-server
just build-android-core
just build-apk
just test
just deploy-all
~~~
