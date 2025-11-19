#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iptypes.h>
#include <stdarg.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#if defined(_MSC_VER)
#define NS_VSCRTF _vscprintf
#else
#define NS_VSCRTF(format, args) vsnprintf(NULL, 0, format, args)
#endif

#define MAX_THREADS 64
#define MIN_PORT 1
#define MAX_PORT 65535
#define INITIAL_LOG_CAPACITY 8192

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

typedef struct {
    DWORD port;
    char ip[256];
} ThreadParam;

typedef struct {
    int start;
    int end;
} PortRange;

typedef struct {
    char* data;
    size_t length;
    size_t capacity;
} OutputLog;

WSADATA wsa;
BOOL wsaInitialized = FALSE;
volatile LONG totalScanned = 0;
volatile LONG totalOpen = 0;
volatile LONG totalClosed = 0;
int timeout = 1000;
int threadCount = 20;
int delayMin = 100;
int delayMax = 2000;
char payloadTemplate[1024] = { 0 };
char requestPath[256] = "/";
char* domainFront = NULL;
char* hostnameSpoofValue = NULL;

PortRange* exclusionRanges = NULL;
size_t exclusionCount = 0;

OutputLog logBuffer = { 0 };
CRITICAL_SECTION outputLock;
CRITICAL_SECTION randLock;
BOOL locksInitialized = FALSE;

const char* userAgents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/8.4.0",
    "Wget/1.21.4 (linux-gnu)",
    "python-requests/2.32.0"
};

const char* httpMethods[] = { "GET", "HEAD", "OPTIONS" };

static void CleanupResources(void);
static void PrintUsage(void);
static BOOL LoadPayloadTemplate(const char* path);
static BOOL LoadExcludedPorts(const char* ports);
static void FreeExcludedPorts(void);
static char* TrimWhitespace(char* value);
static BOOL ParsePortNumber(const char* text, int* value);
static BOOL ParsePortToken(const char* token, int* start, int* end);
static BOOL HandleOption(const char* option, const char** payloadPath, const char** excludeArg, const char** frontArg);
static int RandomBetween(int min, int max);
static DWORD GetJitterDelay(void);
static void InitializeSync(void);
static void CleanupSync(void);
static void AppendToBuffer(const char* format, ...);
static void EnsureLogCapacity(size_t additional);
static void FormatHostHeader(const char* input, char* output, size_t size);
static void ConfigureSocket(SOCKET s, int family);
static void BindRandomSourcePort(SOCKET s, int family);
static BOOL IsExcludedPort(int port);
static BOOL IsAlive(const char* ip, DWORD port);
static DWORD WINAPI ScanPort(LPVOID param);
static void Scan(const char* ip, const char* portList);
static void FlushThreadBatch(HANDLE* threads, DWORD count);
static void ValidateConfig(void);
static void ApplyHostnameSpoof(void);

int InitWSAContext(void) {
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "--help") == 0 || _stricmp(argv[i], "-h") == 0) {
            PrintUsage();
            return 0;
        }
    }

    if (argc < 3) {
        PrintUsage();
        return 1;
    }

    const char* target = argv[1];
    const char* ports = argv[2];
    const char* payloadPathOpt = NULL;
    const char* excludeOpt = NULL;
    const char* frontOpt = NULL;
    const char* positionalPayload = NULL;
    const char* positionalExclude = NULL;
    const char* positionalFront = NULL;
    int positionalIndex = 0;

    for (int i = 3; i < argc; ++i) {
        if (strncmp(argv[i], "--", 2) == 0) {
            if (!HandleOption(argv[i], &payloadPathOpt, &excludeOpt, &frontOpt)) {
                CleanupResources();
                return 1;
            }
            continue;
        }

        switch (positionalIndex) {
        case 0: positionalPayload = argv[i]; break;
        case 1: positionalExclude = argv[i]; break;
        case 2: positionalFront = argv[i]; break;
        default: fprintf(stderr, "[!] Ignoring extra positional argument: %s\n", argv[i]); break;
        }
        positionalIndex++;
    }

    const char* payloadPath = payloadPathOpt ? payloadPathOpt : positionalPayload;
    const char* excludeArg = excludeOpt ? excludeOpt : positionalExclude;
    const char* frontArg = frontOpt ? frontOpt : positionalFront;

    if (payloadPath && !LoadPayloadTemplate(payloadPath)) {
        CleanupResources();
        return 1;
    }

    if (excludeArg && !LoadExcludedPorts(excludeArg)) {
        CleanupResources();
        return 1;
    }

    if (frontArg) {
        domainFront = _strdup(frontArg);
        if (!domainFront) {
            fprintf(stderr, "[!] Failed to allocate memory for domain front value.\n");
            CleanupResources();
            return 1;
        }
    }

    threadCount = max(1, min(threadCount, MAX_THREADS));
    ValidateConfig();

    if (InitWSAContext() != 0) {
        fprintf(stderr, "[!] WSAStartup failed (%lu)\n", GetLastError());
        CleanupResources();
        return 1;
    }
    wsaInitialized = TRUE;

    InitializeSync();
    srand((unsigned int)time(NULL));

    if (hostnameSpoofValue) {
        ApplyHostnameSpoof();
    }

    DWORD startTime = GetTickCount();
    Scan(target, ports);
    DWORD elapsed = GetTickCount() - startTime;

    AppendToBuffer("\n=== Scan Summary ===\n");
    AppendToBuffer("Total: %ld\nOpen: %ld\nClosed: %ld\nTime: %.2fs\n",
        totalScanned, totalOpen, totalClosed, elapsed / 1000.0);

    if (logBuffer.data) {
        printf("%s", logBuffer.data);
    }

    CleanupResources();
    return 0;
}

static void PrintUsage(void) {
    printf("Usage: NomadScanner.exe <target> <ports> [payload.txt] [exclude_ports] [front_host] [options]\n");
    printf("\nOptions:\n");
    printf("  --threads=<1-%d>        Set worker thread count (default 20)\n", MAX_THREADS);
    printf("  --timeout=<ms>          Set socket send/recv timeout (default 1000)\n");
    printf("  --jitter=<min>-<max>    Millisecond jitter before/after probes (default 100-2000)\n");
    printf("  --payload=<path>        Override payload template file\n");
    printf("  --exclude=<ports>       Port exclusions (e.g., 135,445,8000-8100)\n");
    printf("  --front=<host>          Domain front value for Host header\n");
    printf("  --path=<request_path>   HTTP request path (default /)\n");
    printf("  --spoof-hostname=<n>    Set process-level COMPUTERNAME for OPSEC\n");
    printf("  --help                  Show this message\n");
}

static BOOL HandleOption(const char* option, const char** payloadPath, const char** excludeArg, const char** frontArg) {
    if (!option) return FALSE;

    if (_strnicmp(option, "--threads=", 10) == 0) {
        threadCount = atoi(option + 10);
        return TRUE;
    }

    if (_strnicmp(option, "--timeout=", 10) == 0) {
        timeout = atoi(option + 10);
        return TRUE;
    }

    if (_strnicmp(option, "--jitter=", 9) == 0) {
        char buffer[64];
        strncpy(buffer, option + 9, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        char* dash = strchr(buffer, '-');
        if (!dash) {
            fprintf(stderr, "[!] Invalid jitter format. Expected min-max.\n");
            return FALSE;
        }
        *dash = '\0';
        char* maxPart = dash + 1;
        delayMin = atoi(buffer);
        delayMax = atoi(maxPart);
        return TRUE;
    }

    if (_strnicmp(option, "--payload=", 10) == 0) {
        *payloadPath = option + 10;
        return TRUE;
    }

    if (_strnicmp(option, "--exclude=", 10) == 0) {
        *excludeArg = option + 10;
        return TRUE;
    }

    if (_strnicmp(option, "--front=", 8) == 0) {
        *frontArg = option + 8;
        return TRUE;
    }

    if (_strnicmp(option, "--path=", 7) == 0) {
        const char* value = option + 7;
        if (strlen(value) >= sizeof(requestPath)) {
            fprintf(stderr, "[!] Request path too long.\n");
            return FALSE;
        }
        strncpy(requestPath, value, sizeof(requestPath) - 1);
        requestPath[sizeof(requestPath) - 1] = '\0';
        return TRUE;
    }

    if (_strnicmp(option, "--spoof-hostname=", 17) == 0) {
        const char* value = option + 17;
        if (strlen(value) > MAX_COMPUTERNAME_LENGTH) {
            fprintf(stderr, "[!] Hostname exceeds maximum length (%d).\n", MAX_COMPUTERNAME_LENGTH);
            return FALSE;
        }
        free(hostnameSpoofValue);
        hostnameSpoofValue = _strdup(value);
        if (!hostnameSpoofValue) {
            fprintf(stderr, "[!] Failed to allocate hostname string.\n");
            return FALSE;
        }
        return TRUE;
    }

    fprintf(stderr, "[!] Unknown option: %s\n", option);
    return FALSE;
}

static void ValidateConfig(void) {
    if (threadCount < 1) threadCount = 1;
    if (threadCount > MAX_THREADS) threadCount = MAX_THREADS;
    if (timeout < 100) timeout = 100;
    if (timeout > 600000) timeout = 600000;
    if (delayMin < 0) delayMin = 0;
    if (delayMax < delayMin) delayMax = delayMin;
    if (delayMax > 60000) delayMax = 60000;
}

static BOOL LoadPayloadTemplate(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] Failed to open payload template: %s\n", path);
        return FALSE;
    }
    memset(payloadTemplate, 0, sizeof(payloadTemplate));
    size_t read = fread(payloadTemplate, 1, sizeof(payloadTemplate) - 1, f);
    payloadTemplate[read] = '\0';
    fclose(f);
    return TRUE;
}

static BOOL LoadExcludedPorts(const char* ports) {
    if (!ports || !*ports) return TRUE;

    char* copy = _strdup(ports);
    if (!copy) {
        fprintf(stderr, "[!] Failed to duplicate exclude list.\n");
        return FALSE;
    }

    char* token = strtok(copy, ",");
    while (token) {
        char* trimmed = TrimWhitespace(token);
        if (*trimmed) {
            int start, end;
            if (!ParsePortToken(trimmed, &start, &end)) {
                fprintf(stderr, "[!] Invalid exclude token: %s\n", trimmed);
                free(copy);
                FreeExcludedPorts();
                return FALSE;
            }

            PortRange* next = realloc(exclusionRanges, (exclusionCount + 1) * sizeof(PortRange));
            if (!next) {
                fprintf(stderr, "[!] Failed to allocate exclusion range.\n");
                free(copy);
                FreeExcludedPorts();
                return FALSE;
            }
            exclusionRanges = next;
            exclusionRanges[exclusionCount].start = start;
            exclusionRanges[exclusionCount].end = end;
            exclusionCount++;
        }
        token = strtok(NULL, ",");
    }

    free(copy);
    return TRUE;
}

static void FreeExcludedPorts(void) {
    free(exclusionRanges);
    exclusionRanges = NULL;
    exclusionCount = 0;
}

static char* TrimWhitespace(char* value) {
    if (!value) return value;
    while (*value && isspace((unsigned char)*value)) value++;
    if (*value == '\0') return value;

    char* end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char)*end)) {
        *end = '\0';
        --end;
    }
    return value;
}

static BOOL ParsePortNumber(const char* text, int* value) {
    if (!text || !*text || !value) return FALSE;
    char* endPtr = NULL;
    long parsed = strtol(text, &endPtr, 10);
    if (endPtr == text || *endPtr != '\0') return FALSE;
    if (parsed < MIN_PORT || parsed > MAX_PORT) return FALSE;
    *value = (int)parsed;
    return TRUE;
}

static BOOL ParsePortToken(const char* token, int* start, int* end) {
    if (!token || !start || !end) return FALSE;
    const char* dash = strchr(token, '-');
    if (!dash) {
        if (!ParsePortNumber(token, start)) return FALSE;
        *end = *start;
        return TRUE;
    }

    char left[16];
    char right[16];
    size_t leftLen = (size_t)(dash - token);
    size_t rightLen = strlen(dash + 1);
    if (leftLen >= sizeof(left) || rightLen >= sizeof(right)) return FALSE;

    strncpy(left, token, leftLen);
    left[leftLen] = '\0';
    strncpy(right, dash + 1, sizeof(right) - 1);
    right[sizeof(right) - 1] = '\0';

    if (!ParsePortNumber(left, start) || !ParsePortNumber(right, end)) {
        return FALSE;
    }

    if (*end < *start) {
        int tmp = *start;
        *start = *end;
        *end = tmp;
    }
    return TRUE;
}

static BOOL IsExcludedPort(int port) {
    for (size_t i = 0; i < exclusionCount; ++i) {
        if (port >= exclusionRanges[i].start && port <= exclusionRanges[i].end) {
            return TRUE;
        }
    }
    return FALSE;
}

static void InitializeSync(void) {
    InitializeCriticalSection(&outputLock);
    InitializeCriticalSection(&randLock);
    locksInitialized = TRUE;
}

static void CleanupSync(void) {
    if (!locksInitialized) return;
    DeleteCriticalSection(&outputLock);
    DeleteCriticalSection(&randLock);
    locksInitialized = FALSE;
}

static void EnsureLogCapacity(size_t additional) {
    size_t required = logBuffer.length + additional + 1;
    if (required <= logBuffer.capacity) return;

    size_t newCapacity = logBuffer.capacity ? logBuffer.capacity : INITIAL_LOG_CAPACITY;
    while (newCapacity < required) {
        newCapacity *= 2;
    }

    char* next = realloc(logBuffer.data, newCapacity);
    if (!next) return;
    logBuffer.data = next;
    logBuffer.capacity = newCapacity;
}

static void AppendToBuffer(const char* format, ...) {
    if (!locksInitialized) return;
    va_list args;
    va_start(args, format);
    int needed = NS_VSCRTF(format, args);
    va_end(args);
    if (needed <= 0) return;

    EnterCriticalSection(&outputLock);
    EnsureLogCapacity((size_t)needed);
    if (logBuffer.data) {
        va_start(args, format);
        vsnprintf(logBuffer.data + logBuffer.length, logBuffer.capacity - logBuffer.length, format, args);
        va_end(args);
        logBuffer.length += needed;
        logBuffer.data[logBuffer.length] = '\0';
    }
    LeaveCriticalSection(&outputLock);
}

static int RandomBetween(int min, int max) {
    if (max < min) {
        int tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) return min;
    EnterCriticalSection(&randLock);
    int value = rand();
    LeaveCriticalSection(&randLock);
    int span = max - min + 1;
    if (span <= 0) span = 1;
    return min + (value % span);
}

static DWORD GetJitterDelay(void) {
    if (delayMax <= 0) return 0;
    int minVal = delayMin < 0 ? 0 : delayMin;
    int maxVal = (delayMax < minVal) ? minVal : delayMax;
    return (DWORD)RandomBetween(minVal, maxVal);
}

static void FormatHostHeader(const char* input, char* output, size_t size) {
    if (!output || size == 0) return;
    const char* source = (input && *input) ? input : "";
    BOOL needsBrackets = strchr(source, ':') != NULL && source[0] != '[';
    if (needsBrackets) {
        snprintf(output, size, "[%s]", source);
    }
    else {
        snprintf(output, size, "%s", source);
    }
}

static void BindRandomSourcePort(SOCKET s, int family) {
    const int attempts = 5;
    for (int i = 0; i < attempts; ++i) {
        int rndPort = RandomBetween(49152, 65535);
        if (family == AF_INET) {
            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr.s_addr = INADDR_ANY;
            local.sin_port = htons((u_short)rndPort);
            if (bind(s, (SOCKADDR*)&local, sizeof(local)) == 0) return;
        }
        else if (family == AF_INET6) {
            struct sockaddr_in6 local6;
            memset(&local6, 0, sizeof(local6));
            local6.sin6_family = AF_INET6;
            local6.sin6_addr = in6addr_any;
            local6.sin6_port = htons((u_short)rndPort);
            if (bind(s, (SOCKADDR*)&local6, sizeof(local6)) == 0) return;
        }
        else {
            return;
        }
    }
}

static void ConfigureSocket(SOCKET s, int family) {
    BindRandomSourcePort(s, family);

    int win = RandomBetween(4096, 65535);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&win, sizeof(win));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&win, sizeof(win));
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (family == AF_INET) {
        int ttl = RandomBetween(1, 128);
        setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
        int tos = RandomBetween(0, 255);
        setsockopt(s, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos));
        BOOL dontFrag = TRUE;
        setsockopt(s, IPPROTO_IP, IP_DONT_FRAGMENT, (char*)&dontFrag, sizeof(dontFrag));
    }
    else if (family == AF_INET6) {
        int hops = RandomBetween(1, 128);
        setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char*)&hops, sizeof(hops));
        int tclass = RandomBetween(0, 255);
        setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tclass, sizeof(tclass));
        BOOL dontFrag6 = TRUE;
        setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, (char*)&dontFrag6, sizeof(dontFrag6));
    }
}

static BOOL IsAlive(const char* ip, DWORD port) {
    DWORD jitter = GetJitterDelay();
    if (jitter) Sleep(jitter);

    if (IsExcludedPort((int)port)) return FALSE;

    struct addrinfo hints;
    struct addrinfo* results = NULL;
    struct addrinfo* cursor = NULL;
    SOCKET s = INVALID_SOCKET;
    BOOL connected = FALSE;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%lu", port);

    if (getaddrinfo(ip, portStr, &hints, &results) != 0) {
        AppendToBuffer("[!] getaddrinfo failed for %s:%lu (err=%d)\n", ip, port, WSAGetLastError());
        return FALSE;
    }

    for (cursor = results; cursor != NULL; cursor = cursor->ai_next) {
        s = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);
        if (s == INVALID_SOCKET) {
            continue;
        }

        ConfigureSocket(s, cursor->ai_family);

        if (connect(s, cursor->ai_addr, (int)cursor->ai_addrlen) == 0) {
            connected = TRUE;
            break;
        }

        closesocket(s);
        s = INVALID_SOCKET;
    }

    if (!connected || s == INVALID_SOCKET) {
        if (results) freeaddrinfo(results);
        return FALSE;
    }

    const char* method = httpMethods[RandomBetween(0, (int)(sizeof(httpMethods) / sizeof(httpMethods[0])) - 1)];
    const char* ua = userAgents[RandomBetween(0, (int)(sizeof(userAgents) / sizeof(userAgents[0])) - 1)];

    int padLen = RandomBetween(0, 31);
    char pad[32] = { 0 };
    for (int i = 0; i < padLen; ++i) {
        pad[i] = 'A' + RandomBetween(0, 25);
    }
    pad[padLen] = '\0';

    char hostHeader[256];
    const char* hostSource = domainFront ? domainFront : ip;
    FormatHostHeader(hostSource, hostHeader, sizeof(hostHeader));

    char message[1152];
    if (payloadTemplate[0] != '\0') {
        snprintf(message, sizeof(message), payloadTemplate, method, requestPath, hostHeader, ua);
    }
    else {
        snprintf(message, sizeof(message),
            "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s\r\n",
            method, requestPath, hostHeader, ua, padLen ? pad : "");
    }

    send(s, message, (int)strlen(message), 0);

    char banner[256];
    int len = recv(s, banner, sizeof(banner) - 1, 0);
    if (len > 0) {
        banner[len] = '\0';
        AppendToBuffer("[+] Banner from %s:%lu -> %.80s\n", ip, port, banner);
    }

    closesocket(s);
    freeaddrinfo(results);
    return TRUE;
}

static DWORD WINAPI ScanPort(LPVOID param) {
    ThreadParam* p = (ThreadParam*)param;
    if (!p) return 0;

    InterlockedIncrement(&totalScanned);

    if (IsAlive(p->ip, p->port)) {
        InterlockedIncrement(&totalOpen);
        AppendToBuffer("[+] %s:%lu is open\n", p->ip, p->port);
    }
    else {
        InterlockedIncrement(&totalClosed);
        AppendToBuffer("[-] %s:%lu is closed\n", p->ip, p->port);
    }

    DWORD postJitter = GetJitterDelay();
    if (postJitter) Sleep(postJitter);

    free(p);
    return 0;
}

static void FlushThreadBatch(HANDLE* threads, DWORD count) {
    if (!count) return;
    WaitForMultipleObjects(count, threads, TRUE, INFINITE);
    for (DWORD i = 0; i < count; ++i) {
        CloseHandle(threads[i]);
    }
}

static void Scan(const char* ip, const char* portList) {
    if (!ip || !portList) return;

    char* listCopy = _strdup(portList);
    if (!listCopy) {
        AppendToBuffer("[!] Failed to allocate port list buffer.\n");
        return;
    }

    HANDLE threads[MAX_THREADS] = { 0 };
    DWORD active = 0;

    char* token = strtok(listCopy, ",");
    while (token) {
        char* trimmed = TrimWhitespace(token);
        if (*trimmed) {
            int start, end;
            if (!ParsePortToken(trimmed, &start, &end)) {
                AppendToBuffer("[!] Invalid port token: %s\n", trimmed);
            }
            else {
                for (int port = start; port <= end; ++port) {
                    if (IsExcludedPort(port)) continue;
                    ThreadParam* param = (ThreadParam*)malloc(sizeof(ThreadParam));
                    if (!param) {
                        AppendToBuffer("[!] Allocation failed for port %d\n", port);
                        continue;
                    }
                    param->port = (DWORD)port;
                    strncpy(param->ip, ip, sizeof(param->ip) - 1);
                    param->ip[sizeof(param->ip) - 1] = '\0';

                    HANDLE hThread = CreateThread(NULL, 0, ScanPort, param, 0, NULL);
                    if (!hThread) {
                        AppendToBuffer("[!] CreateThread failed for %s:%d (err=%lu)\n", ip, port, GetLastError());
                        free(param);
                        continue;
                    }

                    threads[active++] = hThread;
                    if (active >= (DWORD)threadCount) {
                        FlushThreadBatch(threads, active);
                        active = 0;
                    }
                }
            }
        }
        token = strtok(NULL, ",");
    }

    if (active > 0) {
        FlushThreadBatch(threads, active);
    }

    free(listCopy);
}

static void ApplyHostnameSpoof(void) {
    if (!hostnameSpoofValue || !*hostnameSpoofValue) return;
    if (SetEnvironmentVariableA("COMPUTERNAME", hostnameSpoofValue)) {
        AppendToBuffer("[*] Process COMPUTERNAME spoofed to %s\n", hostnameSpoofValue);
    }
    else {
        AppendToBuffer("[!] Failed to spoof COMPUTERNAME (%lu)\n", GetLastError());
    }
}

static void CleanupResources(void) {
    if (logBuffer.data) {
        free(logBuffer.data);
        logBuffer.data = NULL;
        logBuffer.length = 0;
        logBuffer.capacity = 0;
    }
    if (domainFront) {
        free(domainFront);
        domainFront = NULL;
    }
    if (hostnameSpoofValue) {
        free(hostnameSpoofValue);
        hostnameSpoofValue = NULL;
    }
    FreeExcludedPorts();
    if (wsaInitialized) {
        WSACleanup();
        wsaInitialized = FALSE;
    }
    CleanupSync();
}
