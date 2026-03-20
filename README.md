# NomadScanner

**OPSEC-hardened TCP port scanner for red team and adversary simulation engagements.**

NomadScanner performs in-memory, multithreaded TCP connect scans with randomised network characteristics designed to blend into baseline traffic. All output is buffered in memory and written once at exit — no intermediate disk artifacts.

---

## Features

### Core

- **In-memory output** — single `printf` flush at exit, no file writes
- **Multithreaded** — configurable worker pool (1–64 threads) with batch dispatch
- **IPv4 & IPv6** — dual-stack via `getaddrinfo`, per-family socket tuning
- **Port range & exclusion** syntax — `1-1024`, `80,443,8000-8100`
- **Reliable connect timeout** — non-blocking `connect()` with `WSAPoll()` loop; no silent hangs on filtered ports

### HTTP Probe

- Randomised HTTP method (`GET`, `HEAD`, `OPTIONS`)
- Randomised `User-Agent` from a realistic pool (browsers, curl, wget, python, Go)
- Domain fronting via `--front` (`Host:` header override)
- Custom payload template via `--payload`
- Configurable request path via `--path`
- Junk `X-Req-ID` header with random-length, full printable-ASCII content to vary request fingerprint
- **Banner grabbing is opt-in** (`--banner`) — off by default to minimise log exposure

### Network Stealth

- **`CryptGenRandom`-backed CSPRNG** for all entropy (source ports, TTL, TOS, padding, window sizes) replaces `rand()` entirely
- **Realistic TTL values** sampled from OS fingerprint buckets (64 / 128 / 255) with ±3 variance no constant or obviously-random values
- **Realistic DSCP/TOS** — weighted toward CS0 (the vast majority of real traffic), with occasional CS1/CS2/CS6
- **Random ephemeral source port** per connection (IANA dynamic range 49152–65535)
- **Randomised TCP window and buffer sizes** per socket
- **`TCP_NODELAY`** and **DF bit** set per-family
- **Pre/post connection jitter** (configurable `min-max` ms range)

---

## Build

### MSVC (recommended)

```bat
cl /O2 /W4 NomadScanner.c /link ws2_32.lib iphlpapi.lib advapi32.lib
```

### MinGW

```bash
gcc -O3 -s -o NomadScanner.exe NomadScanner.c -lws2_32 -liphlpapi -ladvapi32
```

> `advapi32` is required for `CryptGenRandom` / `CryptAcquireContext`.

---

## Usage

```
NomadScanner.exe <target> <ports> [options]
```

| Flag | Description | Default |
|---|---|---|
| `--threads=<1-64>` | Worker thread count | `20` |
| `--timeout=<ms>` | Connect + recv timeout | `1000` |
| `--jitter=<min>-<max>` | Per-probe delay range in ms | `100-2000` |
| `--payload=<path>` | HTTP payload template file | — |
| `--exclude=<ports>` | Excluded ports, e.g. `135,445,8000-8100` | — |
| `--front=<host>` | Domain front (`Host:` header override) | — |
| `--path=<path>` | HTTP request path | `/` |
| `--banner` | Enable banner grabbing (opt-in) | off |
| `--help` | Show usage | — |

### Examples

```bat
REM Basic scan
NomadScanner.exe 192.168.1.1 80,443

REM Range scan with exclusions
NomadScanner.exe 10.0.0.1 1-1024 --exclude=135,445

REM Domain fronting with banner grab
NomadScanner.exe 10.0.0.5 80,443,8080 --front=www.microsoft.com --banner

REM Low-and-slow with high jitter
NomadScanner.exe 10.0.0.1 1-65535 --threads=5 --jitter=500-5000 --timeout=3000
```

---

## Payload Template

If `--payload` is specified, the file is used as a raw HTTP request format string.
Four positional `%s` arguments are substituted in order:

```
%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n
```

1. HTTP method (`GET` / `HEAD` / `OPTIONS`)
2. Request path (value of `--path`, default `/`)
3. Host header (domain front if `--front` is set; IPv6 literals are auto-bracketed)
4. User-Agent string

---


## Legal

For **authorised use only** — red team engagements, penetration tests, lab research, and internal security tooling. Do not use against systems without explicit written permission.

---

## License

MIT — see `LICENSE`.

## Shoutout

Huge thanks to https://github.com/mr-un1k0d3r for his courses and inspirational coding videos.
