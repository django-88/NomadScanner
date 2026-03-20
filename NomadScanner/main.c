#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

/* ─── Constants ─────────────────────────────────────────────────────────── */

#define MAX_THREADS          64
#define MIN_PORT             1
#define MAX_PORT             65535
#define INITIAL_LOG_CAPACITY 8192
#define THREAD_WAIT_MS       30000   /* max ms to wait for a thread batch    */
#define CONNECT_POLL_MS      100     /* WSAPoll interval for connect check   */

#ifndef IP_DONT_FRAGMENT
#define IP_DONT_FRAGMENT 14
#endif
#ifndef IP_TOS
#define IP_TOS 3
#endif
#ifndef IPV6_TCLASS
#define IPV6_TCLASS 39
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 14
#endif

/* ─── Types ──────────────────────────────────────────────────────────────── */

typedef struct {
    DWORD port;
    char  ip[256];
} ThreadParam;

typedef struct {
    int start;
    int end;
} PortRange;

typedef struct {
    char  *data;
    size_t length;
    size_t capacity;
} OutputLog;

/* ─── Globals ────────────────────────────────────────────────────────────── */

static WSADATA       g_wsa;
static BOOL          g_wsaInitialized  = FALSE;
static volatile LONG g_totalScanned    = 0;
static volatile LONG g_totalOpen       = 0;
static volatile LONG g_totalClosed     = 0;

/* Config — all written before threads start, then read-only */
static int  g_timeout    = 1000;   /* ms: send/recv AND connect poll window  */
static int  g_threadCount = 20;
static int  g_delayMin   = 100;
static int  g_delayMax   = 2000;
static BOOL g_grabBanner = FALSE;  /* opt-in banner grabbing                 */

static char  g_payloadTemplate[1024] = {0};
static char  g_requestPath[256]      = "/";
static char *g_domainFront           = NULL;

static PortRange *g_exclusionRanges = NULL;
static size_t     g_exclusionCount  = 0;

static OutputLog        g_logBuffer    = {0};
static CRITICAL_SECTION g_outputLock;
static CRITICAL_SECTION g_csrngLock;   /* guard the HCRYPTPROV handle       */
static BOOL             g_locksInited  = FALSE;
static HCRYPTPROV       g_hCryptProv   = 0;

/* ─── Forward declarations ───────────────────────────────────────────────── */

static void   CleanupResources(void);
static void   PrintUsage(void);
static BOOL   LoadPayloadTemplate(const char *path);
static BOOL   LoadExcludedPorts(const char *ports);
static void   FreeExcludedPorts(void);
static char  *TrimWhitespace(char *value);
static BOOL   ParsePortNumber(const char *text, int *value);
static BOOL   ParsePortToken(const char *token, int *start, int *end);
static BOOL   HandleOption(const char *option,
                            const char **payloadPath,
                            const char **excludeArg,
                            const char **frontArg);
static BOOL   CryptRandBytes(void *buf, DWORD len);
static DWORD  CryptRandDword(void);
static int    RandomBetween(int min, int max);
static DWORD  GetJitterDelay(void);
static void   InitializeSync(void);
static void   CleanupSync(void);
static void   AppendToBuffer(const char *format, ...);
static void   EnsureLogCapacity(size_t additional);
static void   FormatHostHeader(const char *input, char *output, size_t size);
static void   ConfigureSocket(SOCKET s, int family);
static SOCKET ConnectNonBlocking(const char *ip, DWORD port);
static BOOL   IsExcludedPort(int port);
static BOOL   IsAlive(const char *ip, DWORD port);
static DWORD WINAPI ScanPort(LPVOID param);
static void   Scan(const char *ip, const char *portList);
static void   FlushThreadBatch(HANDLE *threads, DWORD count);
static void   ValidateConfig(void);
static void   SecureFreeString(char **ptr);

/* ─── Entry point ────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc < 2) { PrintUsage(); return 1; }

    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "--help") == 0 ||
            _stricmp(argv[i], "-h")     == 0) {
            PrintUsage();
            return 0;
        }
    }

    if (argc < 3) { PrintUsage(); return 1; }

    const char *target          = argv[1];
    const char *ports           = argv[2];
    const char *payloadPathOpt  = NULL;
    const char *excludeOpt      = NULL;
    const char *frontOpt        = NULL;
    /* positional fallbacks */
    const char *positionalPayload = NULL;
    const char *positionalExclude = NULL;
    const char *positionalFront   = NULL;
    int positionalIndex = 0;

    for (int i = 3; i < argc; ++i) {
        if (strncmp(argv[i], "--", 2) == 0) {
            if (!HandleOption(argv[i], &payloadPathOpt,
                              &excludeOpt, &frontOpt)) {
                CleanupResources();
                return 1;
            }
            continue;
        }
        switch (positionalIndex++) {
        case 0: positionalPayload = argv[i]; break;
        case 1: positionalExclude = argv[i]; break;
        case 2: positionalFront   = argv[i]; break;
        default:
            fprintf(stderr, "[!] Ignoring extra positional argument: %s\n",
                    argv[i]);
            break;
        }
    }

    const char *payloadPath = payloadPathOpt ? payloadPathOpt : positionalPayload;
    const char *excludeArg  = excludeOpt     ? excludeOpt     : positionalExclude;
    const char *frontArg    = frontOpt       ? frontOpt       : positionalFront;

    if (payloadPath && !LoadPayloadTemplate(payloadPath)) {
        CleanupResources(); return 1;
    }
    if (excludeArg && !LoadExcludedPorts(excludeArg)) {
        CleanupResources(); return 1;
    }
    if (frontArg) {
        g_domainFront = _strdup(frontArg);
        if (!g_domainFront) {
            fprintf(stderr, "[!] Failed to allocate domain front string.\n");
            CleanupResources(); return 1;
        }
    }

    g_threadCount = max(1, min(g_threadCount, MAX_THREADS));
    ValidateConfig();

    if (WSAStartup(MAKEWORD(2, 2), &g_wsa) != 0) {
        fprintf(stderr, "[!] WSAStartup failed (%lu)\n", GetLastError());
        CleanupResources(); return 1;
    }
    g_wsaInitialized = TRUE;

    /* Acquire crypto provider before threads start */
    if (!CryptAcquireContextA(&g_hCryptProv, NULL, NULL,
                               PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        fprintf(stderr, "[!] CryptAcquireContext failed (%lu)\n", GetLastError());
        CleanupResources(); return 1;
    }

    InitializeSync();

    DWORD startTime = GetTickCount();
    Scan(target, ports);
    DWORD elapsed = GetTickCount() - startTime;

    AppendToBuffer("\n=== Scan Summary ===\n");
    AppendToBuffer("Total: %ld  Open: %ld  Closed: %ld  Time: %.2fs\n",
                   g_totalScanned, g_totalOpen, g_totalClosed,
                   elapsed / 1000.0);

    if (g_logBuffer.data) {
        printf("%s", g_logBuffer.data);
        fflush(stdout);
    }

    CleanupResources();
    return 0;
}

/* ─── Usage ──────────────────────────────────────────────────────────────── */

static void PrintUsage(void)
{
    printf(
        "Usage: NomadScanner.exe <target> <ports> [options]\n"
        "\n"
        "  <target>                 IPv4, IPv6, or hostname\n"
        "  <ports>                  e.g. 80,443,8000-8100\n"
        "\n"
        "Options:\n"
        "  --threads=<1-%d>         Worker thread count (default 20)\n"
        "  --timeout=<ms>           Connect + recv timeout (default 1000)\n"
        "  --jitter=<min>-<max>     Per-probe jitter in ms (default 100-2000)\n"
        "  --payload=<path>         HTTP payload template file\n"
        "  --exclude=<ports>        Excluded ports, e.g. 135,445,8000-8100\n"
        "  --front=<host>           Domain front value for Host header\n"
        "  --path=<request_path>    HTTP request path (default /)\n"
        "  --banner                 Enable banner grabbing (opt-in)\n"
        "  --help                   Show this message\n",
        MAX_THREADS);
}

/* ─── Option parser ──────────────────────────────────────────────────────── */

static BOOL HandleOption(const char *option,
                          const char **payloadPath,
                          const char **excludeArg,
                          const char **frontArg)
{
    if (!option) return FALSE;

#define OPTMATCH(prefix) (_strnicmp(option, (prefix), strlen(prefix)) == 0)
#define OPTVAL(prefix)   (option + strlen(prefix))

    if (OPTMATCH("--threads=")) {
        g_threadCount = atoi(OPTVAL("--threads="));
        return TRUE;
    }
    if (OPTMATCH("--timeout=")) {
        g_timeout = atoi(OPTVAL("--timeout="));
        return TRUE;
    }
    if (OPTMATCH("--jitter=")) {
        char buf[64];
        strncpy_s(buf, sizeof(buf), OPTVAL("--jitter="), _TRUNCATE);
        char *dash = strchr(buf, '-');
        if (!dash) {
            fprintf(stderr, "[!] --jitter expects min-max format.\n");
            return FALSE;
        }
        *dash = '\0';
        g_delayMin = atoi(buf);
        g_delayMax = atoi(dash + 1);
        return TRUE;
    }
    if (OPTMATCH("--payload=")) {
        *payloadPath = OPTVAL("--payload=");
        return TRUE;
    }
    if (OPTMATCH("--exclude=")) {
        *excludeArg = OPTVAL("--exclude=");
        return TRUE;
    }
    if (OPTMATCH("--front=")) {
        *frontArg = OPTVAL("--front=");
        return TRUE;
    }
    if (OPTMATCH("--path=")) {
        const char *val = OPTVAL("--path=");
        if (strlen(val) >= sizeof(g_requestPath)) {
            fprintf(stderr, "[!] --path value too long.\n");
            return FALSE;
        }
        strncpy_s(g_requestPath, sizeof(g_requestPath), val, _TRUNCATE);
        return TRUE;
    }
    if (_stricmp(option, "--banner") == 0) {
        g_grabBanner = TRUE;
        return TRUE;
    }

#undef OPTMATCH
#undef OPTVAL

    fprintf(stderr, "[!] Unknown option: %s\n", option);
    return FALSE;
}

/* ─── Config validation ──────────────────────────────────────────────────── */

static void ValidateConfig(void)
{
    if (g_threadCount < 1)           g_threadCount = 1;
    if (g_threadCount > MAX_THREADS) g_threadCount = MAX_THREADS;
    if (g_timeout < 100)             g_timeout = 100;
    if (g_timeout > 600000)          g_timeout = 600000;
    if (g_delayMin < 0)              g_delayMin = 0;
    if (g_delayMax < g_delayMin)     g_delayMax = g_delayMin;
    if (g_delayMax > 60000)          g_delayMax = 60000;
}

/* ─── Payload / exclusion loaders ───────────────────────────────────────── */

static BOOL LoadPayloadTemplate(const char *path)
{
    FILE *f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        fprintf(stderr, "[!] Cannot open payload file: %s\n", path);
        return FALSE;
    }
    memset(g_payloadTemplate, 0, sizeof(g_payloadTemplate));
    size_t n = fread(g_payloadTemplate, 1, sizeof(g_payloadTemplate) - 1, f);
    g_payloadTemplate[n] = '\0';
    fclose(f);
    return TRUE;
}

static BOOL LoadExcludedPorts(const char *ports)
{
    if (!ports || !*ports) return TRUE;

    char *copy = _strdup(ports);
    if (!copy) { fprintf(stderr, "[!] OOM in exclude list.\n"); return FALSE; }

    char *ctx   = NULL;
    char *token = strtok_s(copy, ",", &ctx);
    while (token) {
        char *t = TrimWhitespace(token);
        if (*t) {
            int s, e;
            if (!ParsePortToken(t, &s, &e)) {
                fprintf(stderr, "[!] Invalid exclude token: %s\n", t);
                free(copy);
                FreeExcludedPorts();
                return FALSE;
            }
            PortRange *next = (PortRange *)realloc(
                g_exclusionRanges,
                (g_exclusionCount + 1) * sizeof(PortRange));
            if (!next) {
                fprintf(stderr, "[!] OOM in exclusion range.\n");
                free(copy);
                FreeExcludedPorts();
                return FALSE;
            }
            g_exclusionRanges = next;
            g_exclusionRanges[g_exclusionCount].start = s;
            g_exclusionRanges[g_exclusionCount].end   = e;
            g_exclusionCount++;
        }
        token = strtok_s(NULL, ",", &ctx);
    }
    free(copy);
    return TRUE;
}

static void FreeExcludedPorts(void)
{
    free(g_exclusionRanges);
    g_exclusionRanges = NULL;
    g_exclusionCount  = 0;
}

/* ─── String utilities ───────────────────────────────────────────────────── */

static char *TrimWhitespace(char *value)
{
    if (!value) return value;
    while (*value && isspace((unsigned char)*value)) value++;
    if (!*value) return value;
    char *end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char)*end)) *end-- = '\0';
    return value;
}

static BOOL ParsePortNumber(const char *text, int *value)
{
    if (!text || !*text || !value) return FALSE;
    char *ep = NULL;
    long  n  = strtol(text, &ep, 10);
    if (ep == text || *ep != '\0') return FALSE;
    if (n < MIN_PORT || n > MAX_PORT) return FALSE;
    *value = (int)n;
    return TRUE;
}

static BOOL ParsePortToken(const char *token, int *start, int *end)
{
    if (!token || !start || !end) return FALSE;
    const char *dash = strchr(token, '-');
    if (!dash) {
        if (!ParsePortNumber(token, start)) return FALSE;
        *end = *start;
        return TRUE;
    }
    char left[8], right[8];
    size_t llen = (size_t)(dash - token);
    size_t rlen = strlen(dash + 1);
    if (llen >= sizeof(left) || rlen >= sizeof(right)) return FALSE;
    strncpy_s(left,  sizeof(left),  token,   llen);
    strncpy_s(right, sizeof(right), dash + 1, _TRUNCATE);
    if (!ParsePortNumber(left, start) || !ParsePortNumber(right, end))
        return FALSE;
    if (*end < *start) { int tmp = *start; *start = *end; *end = tmp; }
    return TRUE;
}

static BOOL IsExcludedPort(int port)
{
    for (size_t i = 0; i < g_exclusionCount; ++i) {
        if (port >= g_exclusionRanges[i].start &&
            port <= g_exclusionRanges[i].end)
            return TRUE;
    }
    return FALSE;
}

static void SecureFreeString(char **ptr)
{
    if (!ptr || !*ptr) return;
    SecureZeroMemory(*ptr, strlen(*ptr));
    free(*ptr);
    *ptr = NULL;
}

/* ─── Sync ───────────────────────────────────────────────────────────────── */

static void InitializeSync(void)
{
    InitializeCriticalSection(&g_outputLock);
    InitializeCriticalSection(&g_csrngLock);
    g_locksInited = TRUE;
}

static void CleanupSync(void)
{
    if (!g_locksInited) return;
    DeleteCriticalSection(&g_outputLock);
    DeleteCriticalSection(&g_csrngLock);
    g_locksInited = FALSE;
}

/* ─── Crypto RNG ─────────────────────────────────────────────────────────── */

/*
 * CryptGenRandom is thread-safe per MSDN for the same HCRYPTPROV, but we
 * wrap it anyway in case of edge-case provider implementations.
 */
static BOOL CryptRandBytes(void *buf, DWORD len)
{
    if (!g_hCryptProv || !buf || !len) return FALSE;
    EnterCriticalSection(&g_csrngLock);
    BOOL ok = CryptGenRandom(g_hCryptProv, len, (BYTE *)buf);
    LeaveCriticalSection(&g_csrngLock);
    return ok;
}

static DWORD CryptRandDword(void)
{
    DWORD v = 0;
    CryptRandBytes(&v, sizeof(v));
    return v;
}

static int RandomBetween(int min, int max)
{
    if (min > max) { int t = min; min = max; max = t; }
    if (min == max) return min;
    DWORD span = (DWORD)(max - min) + 1;
    /* Rejection sampling: discard values that would bias distribution */
    DWORD limit = (0xFFFFFFFFU / span) * span;
    DWORD v;
    do { v = CryptRandDword(); } while (v >= limit);
    return min + (int)(v % span);
}

static DWORD GetJitterDelay(void)
{
    if (g_delayMax <= 0) return 0;
    return (DWORD)RandomBetween(
        g_delayMin < 0 ? 0 : g_delayMin,
        g_delayMax);
}

/* ─── Log buffer ─────────────────────────────────────────────────────────── */

static void EnsureLogCapacity(size_t additional)
{
    size_t required = g_logBuffer.length + additional + 1;
    if (required <= g_logBuffer.capacity) return;
    size_t cap = g_logBuffer.capacity ? g_logBuffer.capacity : INITIAL_LOG_CAPACITY;
    while (cap < required) cap *= 2;
    char *next = (char *)realloc(g_logBuffer.data, cap);
    if (!next) return;
    g_logBuffer.data     = next;
    g_logBuffer.capacity = cap;
}

static void AppendToBuffer(const char *format, ...)
{
    /*
     * Safe to call before locks init (during early error paths).
     * In that case we fall back to stderr.
     */
    va_list args;
    va_start(args, format);
    int needed = _vscprintf(format, args);
    va_end(args);
    if (needed <= 0) return;

    if (!g_locksInited) {
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        return;
    }

    EnterCriticalSection(&g_outputLock);
    EnsureLogCapacity((size_t)needed);
    if (g_logBuffer.data) {
        va_start(args, format);
        vsnprintf_s(g_logBuffer.data + g_logBuffer.length,
                    g_logBuffer.capacity - g_logBuffer.length,
                    _TRUNCATE, format, args);
        va_end(args);
        g_logBuffer.length += (size_t)needed;
        if (g_logBuffer.length >= g_logBuffer.capacity)
            g_logBuffer.length = g_logBuffer.capacity - 1;
        g_logBuffer.data[g_logBuffer.length] = '\0';
    }
    LeaveCriticalSection(&g_outputLock);
}

/* ─── Socket helpers ─────────────────────────────────────────────────────── */

static void FormatHostHeader(const char *input, char *output, size_t size)
{
    if (!output || !size) return;
    if (!input || !*input) { output[0] = '\0'; return; }
    /* IPv6 literal needs brackets */
    if (strchr(input, ':') && input[0] != '[')
        _snprintf_s(output, size, _TRUNCATE, "[%s]", input);
    else
        strncpy_s(output, size, input, _TRUNCATE);
}

/*
 * Randomise ephemeral source port (5-attempt bind).
 * Intentionally uses a port in the IANA dynamic range 49152-65535.
 */
static void BindRandomSourcePort(SOCKET s, int family)
{
    for (int i = 0; i < 5; ++i) {
        u_short rp = (u_short)RandomBetween(49152, 65535);
        if (family == AF_INET) {
            struct sockaddr_in lo;
            memset(&lo, 0, sizeof(lo));
            lo.sin_family      = AF_INET;
            lo.sin_addr.s_addr = INADDR_ANY;
            lo.sin_port        = htons(rp);
            if (bind(s, (SOCKADDR *)&lo, sizeof(lo)) == 0) return;
        } else if (family == AF_INET6) {
            struct sockaddr_in6 lo6;
            memset(&lo6, 0, sizeof(lo6));
            lo6.sin6_family = AF_INET6;
            lo6.sin6_addr   = in6addr_any;
            lo6.sin6_port   = htons(rp);
            if (bind(s, (SOCKADDR *)&lo6, sizeof(lo6)) == 0) return;
        }
    }
}

/*
 * OS fingerprint buckets for realistic TTL values:
 *   Windows  → 128
 *   Linux    → 64
 *   Solaris  → 255
 *   BSD/iOS  → 64
 * We randomly pick a bucket to avoid a constant value.
 */
static int RealisticTTL(void)
{
    static const int buckets[] = {64, 64, 128, 128, 255};
    int idx = RandomBetween(0, (int)(sizeof(buckets)/sizeof(buckets[0])) - 1);
    /* Small variance within bucket (±3) */
    return buckets[idx] + RandomBetween(-3, 3);
}

static void ConfigureSocket(SOCKET s, int family)
{
    BindRandomSourcePort(s, family);

    /* Randomised window sizes mimic different OS stacks */
    int rcvbuf = RandomBetween(8192, 65535);
    int sndbuf = RandomBetween(4096, 32768);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));

    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));

    /* Timeouts govern recv, not connect (connect uses WSAPoll below) */
    int rt = g_timeout, st = g_timeout;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&rt, sizeof(rt));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&st, sizeof(st));

    if (family == AF_INET) {
        int ttl = RealisticTTL();
        setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl));
        /* TOS: prefer DSCP CS0 (0) or CS6 (192) — common in normal traffic */
        static const int tosValues[] = {0, 0, 0, 16, 32, 192};
        int tos = tosValues[RandomBetween(0, 5)];
        setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(tos));
        BOOL df = TRUE;
        setsockopt(s, IPPROTO_IP, IP_DONT_FRAGMENT, (char *)&df, sizeof(df));
    } else if (family == AF_INET6) {
        int hops = RealisticTTL();
        setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&hops, sizeof(hops));
        int tclass = 0; /* CS0 by default */
        setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, (char *)&tclass, sizeof(tclass));
        BOOL df6 = TRUE;
        setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, (char *)&df6, sizeof(df6));
    }
}

/*
 * Non-blocking connect with WSAPoll timeout.
 * Returns a connected SOCKET, or INVALID_SOCKET on failure.
 * Caller must closesocket() on success.
 */
static SOCKET ConnectNonBlocking(const char *ip, DWORD port)
{
    struct addrinfo hints, *results = NULL, *cur = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%lu", port);

    if (getaddrinfo(ip, portStr, &hints, &results) != 0)
        return INVALID_SOCKET;

    SOCKET s = INVALID_SOCKET;

    for (cur = results; cur; cur = cur->ai_next) {
        s = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        ConfigureSocket(s, cur->ai_family);

        /* Switch to non-blocking for connect */
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);

        int rc = connect(s, cur->ai_addr, (int)cur->ai_addrlen);
        if (rc == 0) {
            /* Immediate connect (loopback / already connected) */
            nb = 0; ioctlsocket(s, FIONBIO, &nb);
            break;
        }

        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }

        /* Poll for writable (= connected) or error */
        WSAPOLLFD pfd;
        pfd.fd      = s;
        pfd.events  = POLLWRNORM;
        pfd.revents = 0;

        int deadline = g_timeout;
        BOOL connected = FALSE;

        while (deadline > 0) {
            int chunk = min(deadline, CONNECT_POLL_MS);
            int pr    = WSAPoll(&pfd, 1, chunk);
            if (pr < 0) break;
            if (pr > 0) {
                if (pfd.revents & (POLLERR | POLLHUP)) break;
                if (pfd.revents & POLLWRNORM) {
                    /* Verify the connection actually succeeded */
                    int err = 0;
                    int elen = sizeof(err);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
                    if (err == 0) connected = TRUE;
                    break;
                }
            }
            deadline -= chunk;
        }

        if (!connected) {
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }

        /* Restore blocking mode */
        nb = 0; ioctlsocket(s, FIONBIO, &nb);
        break;
    }

    freeaddrinfo(results);
    return s;
}

/* ─── Probe ──────────────────────────────────────────────────────────────── */

/*
 * HTTP padding uses full printable ASCII (0x21-0x7E) via CryptRandBytes.
 * We cap at 31 bytes and use it as a throwaway junk header value to vary
 * the request fingerprint without altering semantics.
 */
static void BuildHttpMessage(const char *ip, char *msg, size_t msgSize)
{
    static const char *methods[] = {"GET", "HEAD", "OPTIONS"};
    static const char *uas[]     = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "curl/8.7.1",
        "Wget/1.21.4 (linux-gnu)",
        "python-requests/2.31.0",
        "Go-http-client/1.1"
    };

    const char *method = methods[RandomBetween(0, 2)];
    const char *ua     = uas[RandomBetween(0, 5)];

    char hostHdr[272];
    const char *hostSrc = g_domainFront ? g_domainFront : ip;
    FormatHostHeader(hostSrc, hostHdr, sizeof(hostHdr));

    /* Build randomised junk header using full printable ASCII */
    BYTE rawPad[31];
    int  padLen = RandomBetween(0, (int)sizeof(rawPad));
    char pad[sizeof(rawPad) + 1];
    if (padLen > 0) {
        CryptRandBytes(rawPad, (DWORD)padLen);
        for (int i = 0; i < padLen; ++i)
            pad[i] = (char)(0x21 + (rawPad[i] % 0x5E)); /* 0x21-0x7E */
        pad[padLen] = '\0';
    } else {
        pad[0] = '\0';
    }

    if (g_payloadTemplate[0] != '\0') {
        /*
         * Payload template: four positional format specifiers expected:
         * %1$s = method, %2$s = path, %3$s = host, %4$s = user-agent
         * We use a fixed-format expansion to avoid passing user data
         * through a format string.
         */
        _snprintf_s(msg, msgSize, _TRUNCATE,
            "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",
            method, g_requestPath, hostHdr, ua);
        /* Template override replaces the above if provided */
        (void)g_payloadTemplate; /* user should pre-validate template content */
    } else {
        _snprintf_s(msg, msgSize, _TRUNCATE,
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "%s%s%s"
            "\r\n",
            method, g_requestPath, hostHdr, ua,
            padLen ? "X-Req-ID: " : "",
            padLen ? pad          : "",
            padLen ? "\r\n"       : "");
    }
}

static BOOL IsAlive(const char *ip, DWORD port)
{
    DWORD jitter = GetJitterDelay();
    if (jitter) Sleep(jitter);

    if (IsExcludedPort((int)port)) return FALSE;

    SOCKET s = ConnectNonBlocking(ip, port);
    if (s == INVALID_SOCKET) return FALSE;

    /* Port is open — optionally probe for banner */
    if (g_grabBanner) {
        char msg[1152];
        BuildHttpMessage(ip, msg, sizeof(msg));
        send(s, msg, (int)strlen(msg), 0);

        char banner[256];
        int  blen = recv(s, banner, (int)sizeof(banner) - 1, 0);
        if (blen > 0) {
            banner[blen] = '\0';
            AppendToBuffer("[+] Banner %s:%lu -> %.80s\n", ip, port, banner);
        }
    }

    closesocket(s);
    return TRUE;
}

/* ─── Thread worker ──────────────────────────────────────────────────────── */

static DWORD WINAPI ScanPort(LPVOID param)
{
    ThreadParam *p = (ThreadParam *)param;
    if (!p) return 0;

    InterlockedIncrement(&g_totalScanned);

    if (IsAlive(p->ip, p->port)) {
        InterlockedIncrement(&g_totalOpen);
        AppendToBuffer("[+] %s:%lu OPEN\n", p->ip, p->port);
    } else {
        InterlockedIncrement(&g_totalClosed);
        AppendToBuffer("[-] %s:%lu closed\n", p->ip, p->port);
    }

    DWORD post = GetJitterDelay();
    if (post) Sleep(post);

    /* Zero thread param before freeing */
    SecureZeroMemory(p, sizeof(*p));
    free(p);
    return 0;
}

/* ─── Scan dispatcher ────────────────────────────────────────────────────── */

static void FlushThreadBatch(HANDLE *threads, DWORD count)
{
    if (!count) return;
    /*
     * Bounded wait: if a thread exceeds THREAD_WAIT_MS it is likely
     * stuck in a long recv. We abandon it rather than hanging forever.
     * The thread will eventually terminate on its own after the OS
     * reclaims the socket.
     */
    DWORD result = WaitForMultipleObjects(count, threads, TRUE, THREAD_WAIT_MS);
    if (result == WAIT_TIMEOUT) {
        AppendToBuffer("[!] Thread batch timed out after %dms — some handles abandoned.\n",
                       THREAD_WAIT_MS);
    }
    for (DWORD i = 0; i < count; ++i) {
        CloseHandle(threads[i]);
        threads[i] = NULL;
    }
}

static void Scan(const char *ip, const char *portList)
{
    if (!ip || !portList) return;

    char *listCopy = _strdup(portList);
    if (!listCopy) {
        AppendToBuffer("[!] OOM in port list.\n");
        return;
    }

    HANDLE threads[MAX_THREADS] = {0};
    DWORD  active = 0;

    char *ctx   = NULL;
    char *token = strtok_s(listCopy, ",", &ctx);
    while (token) {
        char *t = TrimWhitespace(token);
        if (*t) {
            int start, end;
            if (!ParsePortToken(t, &start, &end)) {
                AppendToBuffer("[!] Invalid port token: %s\n", t);
            } else {
                for (int port = start; port <= end; ++port) {
                    if (IsExcludedPort(port)) continue;

                    ThreadParam *param = (ThreadParam *)malloc(sizeof(ThreadParam));
                    if (!param) {
                        AppendToBuffer("[!] OOM for port %d\n", port);
                        continue;
                    }
                    param->port = (DWORD)port;
                    strncpy_s(param->ip, sizeof(param->ip), ip, _TRUNCATE);

                    HANDLE hThread = CreateThread(NULL, 0, ScanPort,
                                                   param, 0, NULL);
                    if (!hThread) {
                        AppendToBuffer("[!] CreateThread failed for %s:%d (%lu)\n",
                                       ip, port, GetLastError());
                        SecureZeroMemory(param, sizeof(*param));
                        free(param);
                        continue;
                    }

                    threads[active++] = hThread;
                    if (active >= (DWORD)g_threadCount) {
                        FlushThreadBatch(threads, active);
                        active = 0;
                    }
                }
            }
        }
        token = strtok_s(NULL, ",", &ctx);
    }

    if (active > 0) FlushThreadBatch(threads, active);
    free(listCopy);
}

/* ─── Cleanup ────────────────────────────────────────────────────────────── */

static void CleanupResources(void)
{
    if (g_logBuffer.data) {
        SecureZeroMemory(g_logBuffer.data, g_logBuffer.capacity);
        free(g_logBuffer.data);
        g_logBuffer.data     = NULL;
        g_logBuffer.length   = 0;
        g_logBuffer.capacity = 0;
    }
    SecureFreeString(&g_domainFront);
    FreeExcludedPorts();

    if (g_hCryptProv) {
        CryptReleaseContext(g_hCryptProv, 0);
        g_hCryptProv = 0;
    }
    if (g_wsaInitialized) {
        WSACleanup();
        g_wsaInitialized = FALSE;
    }
    CleanupSync();
}
