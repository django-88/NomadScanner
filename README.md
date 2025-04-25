# NomadScanner - Stealth Portscanner for Red Teams

**NomadScanner** is a hardened, memory-only Windows port scanner built for red teamers and penetration testers who need maximum stealth and OPSEC. It sends fully in-memory HTTP probes with randomized network characteristics to blend into normal traffic patterns.

---

## Features

- **In-memory output** (no file writes or disk artifacts)
- **Console-based** for scriptable integration
- **Multithreaded scanning** with configurable jitter (pre/post connection delays)
- **IPv4 & IPv6** support via `getaddrinfo`
- **Randomized HTTP probes**
  - Shuffles between `GET`, `HEAD`, and `OPTIONS`
  - Random `User-Agent` strings
  - Variable HTTP padding (random-length junk after headers)
- **Domain fronting** (custom `Host:` header)
- **Custom payload templates** for bespoke requests
- **Banner grabbing** of service responses
- **Port range & exclusion** syntax (e.g., `1-1024`, `135,445`)
- **Hostname spoofing** (machine name impersonation)
- **MAC address spoof stub** for future extension

### Advanced Network Stealth

- **Random ephemeral source port** binding (49152–65535)
- **Variable IP TTL** (1–128) to evade simple TTL-based filters
- **Random IP TOS** values to alter packet priority bits
- **Set IP “Don’t Fragment” bit** to control path MTU behaviors
- **Dynamic TCP window size** tuning and **Nagle disabling** (`TCP_NODELAY`)
- **Pre-connection jitter** delays to mimic user behavior



---

## Usage

```bash
NomadScanner.exe <target_ip> <ports> [payload.txt] [exclude_ports] [fronting_host]
```

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

If using a `payload.txt` file, use placeholders:

```http
%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n
```

Where:
- 1st`%s`:HTTP method
- 2nd`%s`:request path
- 3rd`%s`:host or domain front
- 4th`%s`:randomized `User-Agent`
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