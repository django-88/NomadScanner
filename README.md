# 🕵️ NomadScanner - Stealth Portscanner for Red Teams

**NomadScanner** is a stealthy, memory-only Windows port scanner designed for red team operations, evasion testing, and internal assessments. It uses randomized HTTP probes, domain fronting, in-memory result handling, and optional payloads for scanning without dropping files or generating noisy output.

---

## ✨ Features

- 🔧 **Memory-only output** (no stdout or file writes)
- 🥟 **Multithreaded scanning** with jittered delays
- 🌐 **IPv4 & IPv6** support via getaddrinfo
- 🔎 **Randomized HTTP probes** (GET, HEAD, OPTIONS)
- 👥 **Domain fronting** (custom Host headers)
- 📁 **Custom payload support** (HTTP template style)
- 📄 **Banner grabbing** for fingerprinting
- 📊 **Port exclusion** and range support
- 👚 **Hostname spoofing**
- 🔬 **MAC spoof stub** (for later extension)
- 🔐 **XOR-based string obfuscation function**
- 📊 **No console window** — results shown via `MessageBoxA`

---

## 🚀 Usage

```bash
NomadScanner.exe <target_ip> <ports> [payload.txt] [exclude_ports] [fronting_host]
```

### 🔍 Examples

```bash
# Basic scan
NomadScanner.exe 127.0.0.1 80,443

# Scan port range with exclusions
NomadScanner.exe 10.0.0.1 1-1024 payload.txt 135,445

# Domain fronting example
NomadScanner.exe 10.0.0.5 80-90 payload.txt 135,445 www.microsoft.com
```

---

## 📆 Payload Template (Optional)

If using a `payload.txt` file, use placeholders:

```http
GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n
```

Where:
- `%s` → replaced with fronting domain or IP
- `%s` → replaced with randomized `User-Agent`

---

## 💠 Build Instructions

### 💻 Visual Studio (Recommended)

- Open `NomadScanner.sln`
- Set configuration to `Release x64`
- Build → Output: `x64\Release\NomadScanner.exe`

### 🔧 MinGW (alternative)

```bash
gcc -mwindows -s -O3 -o NomadScanner.exe main.c -lws2_32 -liphlpapi
```

---

## 📁 Recommended Files to Include

```
NomadScanner/
├── main.c
├── NomadScanner.sln
├── NomadScanner.vcxproj
├── NomadScanner.vcxproj.filters
├── payload.txt               # optional
├── .gitignore
├── LICENSE
└── README.md
```

> 🔒 Exclude: `.vs/`, `*.exe`, `*.obj`, `x64/`, `Debug/`, `Release/`

---

## ⚖️ Legal & Ethical Use

NomadScanner is for **authorized use only** — including red teaming, pentesting, lab research, and education. **Do not use this on systems without explicit permission.**

---

## 📄 License

MIT License – see [LICENSE](LICENSE)
