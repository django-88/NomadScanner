# NomadScanner - Stealth Portscanner for Red Teams

**NomadScanner** is a hardened, memory-only Windows port scanner built for red teamers and penetration testers who need maximum stealth and OPSEC. It sends fully in-memory HTTP probes with randomized network characteristics to blend into normal traffic patterns.

---

## Features

- **In-memory output** with thread-safe buffering (no file writes or disk artifacts)
- **Console-based** for scriptable integration
- **Multithreaded scanning** with configurable jitter (pre/post connection delays)
- **IPv4 & IPv6** support via `getaddrinfo` with per-family socket tuning
- **Randomized HTTP probes**
  - Shuffles between `GET`, `HEAD`, and `OPTIONS`
  - Random `User-Agent` strings
  - Variable HTTP padding (random-length junk after headers)
- **Domain fronting** (custom `Host:` header)
- **Custom payload templates** with predictable placeholders
- **Banner grabbing** of service responses
- **Port range & exclusion** syntax (e.g., `1-1024`, `135,445`) parsed once and cached
- **Opt-in process hostname spoofing** (via CLI flag)
- **MAC address spoof stub** for future extension

### Advanced Network Stealth

- **Random ephemeral source port** binding (49152–65535) for IPv4 and IPv6
- **Variable IP TTL / IPv6 hop limit** (1–128) to evade simple TTL-based filters
- **Random IP TOS / IPv6 traffic class** values to alter packet priority bits
- **Set IPv4 “Don’t Fragment” / IPv6 `DONTFRAG`** to control path MTU behaviors
- **Dynamic TCP window size** tuning and **Nagle disabling** (`TCP_NODELAY`)
- **Pre/post connection jitter** delays (configurable min/max) to mimic user behavior



---

## Usage

```bash
NomadScanner.exe <target> <ports> [payload.txt] [exclude_ports] [front_host] [options]
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--threads=<1-64>` | Worker thread count (auto-clamped) | `20` |
| `--timeout=<ms>` | Socket send/recv timeout | `1000` |
| `--jitter=<min>-<max>` | Millisecond jitter applied before/after probes | `100-2000` |
| `--payload=<path>` | Payload template path (overrides positional arg) | — |
| `--exclude=<ports>` | Exclusion list (e.g., `135,445,8000-8100`) | — |
| `--front=<host>` | Domain front / Host header override | — |
| `--path=<request_path>` | HTTP request path | `/` |
| `--spoof-hostname=<name>` | Process-level `COMPUTERNAME` spoof | disabled |
| `--help` | Display the usage guide | — |

Positional arguments remain for backward compatibility; any CLI flag overrides its positional equivalent when both are supplied.

### Examples

```bash
# Basic scan
NomadScanner.exe 127.0.0.1 80,443

# Scan port range with exclusions
NomadScanner.exe 10.0.0.1 1-1024 payload.txt 135,445

# Domain fronting example
NomadScanner.exe 10.0.0.5 80-90 payload.txt 135,445 www.microsoft.com
```

---

## Payload Template (Optional)

If using a `payload.txt` file, supply the four `%s` placeholders below:

```http
%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n
```

Where:
- 1st `%s`: HTTP method (`GET`, `HEAD`, `OPTIONS`)
- 2nd `%s`: request path (defaults to `/`, configurable via `--path`)
- 3rd `%s`: Host header value (domain front if provided; IPv6 literals auto-wrap with `[]`)
- 4th `%s`: randomized `User-Agent`

---

## Build Instructions

### Visual Studio (Recommended)

- Open `NomadScanner.sln`
- Set configuration to `Release x64`
- Build → Output: `x64\Release\NomadScanner.exe`

### MinGW (alternative)

```bash
gcc -mwindows -s -O3 -o NomadScanner.exe main.c -lws2_32 -liphlpapi
```


---

## Legal & Ethical Use

NomadScanner is for **authorized use only** — including red teaming, pentesting, lab research, and education. **Do not use this on systems without explicit permission.**

---

## License

MIT License – see [LICENSE](LICENSE)

---

## TODO / Roadmap

- [ ] Linux version (native or Wine-compatible)
- [ ] BOF (Beacon Object File) port for Cobalt Strike and other C2s
- [ ] Named pipe or in-memory IPC output support
- [ ] Encrypted strings and shellcode-ready compile path

## Shoutout

Huge thanks to https://github.com/mr-un1k0d3r for his courses and inspirational coding videos.