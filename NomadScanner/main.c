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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_THREADS 64

// Some SDKs may not define these:
#ifndef IP_DONT_FRAGMENT
#define IP_DONT_FRAGMENT 14
#endif
#ifndef IP_TOS
#define IP_TOS 3
#endif
#ifndef IP_TTL_OPTION
#define IP_TTL_OPTION 2
#endif

typedef struct {
    DWORD port;
    char ip[128];
} ThreadParam;

WSADATA wsa;
int totalScanned = 0, totalOpen = 0, totalClosed = 0;
int timeout = 1000, threadCount = 20;
int delayMin = 100, delayMax = 2000;
char payloadTemplate[1024] = { 0 };
char* excludedPortsStr = NULL;
char* domainFront = NULL;
char outputBuffer[8192] = { 0 };

const char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "Wget/1.20.3 (linux-gnu)",
    "python-requests/2.25.1"
};

const char* http_methods[] = { "GET", "HEAD", "OPTIONS" };

BOOL IsExcludedPort(int port) {
    if (!excludedPortsStr) return FALSE;
    char* copy = _strdup(excludedPortsStr);
    if (!copy) return FALSE;
    char* token = strtok(copy, ",");
    while (token) {
        if (strchr(token, '-')) {
            int start, end;
            sscanf(token, "%d-%d", &start, &end);
            if (port >= start && port <= end) {
                free(copy);
                return TRUE;
            }
        }
        else {
            if (atoi(token) == port) {
                free(copy);
                return TRUE;
            }
        }
        token = strtok(NULL, ",");
    }
    free(copy);
    return FALSE;
}

void SetHostnameSpoof() {
    // Spoof Windows machine name
    SetComputerNameA("CORP-WINPC01");
}

void SetMacSpoof() {
    // Stub: real implementation would use adapter driver or registry
}

void AppendToBuffer(const char* format, ...) {
    va_list args;
    va_start(args, format);
    size_t len = strlen(outputBuffer);
    vsnprintf(outputBuffer + len, sizeof(outputBuffer) - len - 1, format, args);
    va_end(args);
}

int InitWSAContext() {
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

BOOL IsAlive(const char* ip, DWORD port) {
    // Pre-connection jitter
    Sleep(rand() % delayMin);

    struct addrinfo hints, * res = NULL;
    char portStr[8];
    SOCKET s;

    if (IsExcludedPort(port)) return FALSE;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portStr, sizeof(portStr), "%lu", port);
    if (getaddrinfo(ip, portStr, &hints, &res) != 0) return FALSE;

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return FALSE;
    }

    // Bind to random ephemeral source port
    struct sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    int rndPort = rand() % (65535 - 49152) + 49152;
    local.sin_port = htons((unsigned short)rndPort);
    bind(s, (SOCKADDR*)&local, sizeof(local));

    // Randomize IP TTL
    int ttl = rand() % 128 + 1;
    setsockopt(s, IPPROTO_IP, IP_TTL_OPTION, (char*)&ttl, sizeof(ttl));

    // Randomize IP TOS
    int tos = rand() % 256;
    setsockopt(s, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos));

    // Set Don't Fragment
    BOOL dontFrag = TRUE;
    setsockopt(s, IPPROTO_IP, IP_DONT_FRAGMENT, (char*)&dontFrag, sizeof(dontFrag));

    // Randomize TCP window and disable Nagle
    int win = rand() % (65535 - 4096) + 4096;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&win, sizeof(win));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&win, sizeof(win));
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s);
        freeaddrinfo(res);
        return FALSE;
    }

    const char* method = http_methods[rand() % (sizeof(http_methods) / sizeof(http_methods[0]))];
    const char* ua = user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))];

    // Random HTTP padding
    int padLen = rand() % 32;
    char pad[32];
    for (int i = 0; i < padLen; i++) pad[i] = 'A' + (rand() % 26);
    pad[padLen] = '\0';

    char message[1152];
    if (strlen(payloadTemplate) > 0) {
        snprintf(message, sizeof(message), payloadTemplate, ip, port, ua);
    }
    else {
        snprintf(message, sizeof(message),
            "%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s\r\n",
            method, domainFront ? domainFront : ip, ua, pad);
    }
    send(s, message, strlen(message), 0);

    char banner[256];
    int len = recv(s, banner, sizeof(banner) - 1, 0);
    if (len > 0) {
        banner[len] = '\0';
        AppendToBuffer("[+] Banner from %s:%lu -> %.50s\n", ip, port, banner);
    }

    closesocket(s);
    freeaddrinfo(res);
    return TRUE;
}

DWORD WINAPI ScanPort(LPVOID param) {
    ThreadParam* p = (ThreadParam*)param;
    InterlockedIncrement((volatile LONG*)&totalScanned);

    if (IsAlive(p->ip, p->port)) {
        InterlockedIncrement((volatile LONG*)&totalOpen);
        AppendToBuffer("[+] %s:%lu is open\n", p->ip, p->port);
    }
    else {
        InterlockedIncrement((volatile LONG*)&totalClosed);
        AppendToBuffer("[-] %s:%lu is closed\n", p->ip, p->port);
    }

    Sleep((DWORD)(delayMin + rand() % (delayMax - delayMin)));
    free(p);
    return 0;
}

void Scan(char* ip, char* port_list) {
    char* token = strtok(port_list, ",");
    HANDLE threads[MAX_THREADS];
    int active = 0;

    while (token) {
        int start, end;
        if (strchr(token, '-')) {
            sscanf(token, "%d-%d", &start, &end);
        }
        else {
            start = end = atoi(token);
        }

        for (int port = start; port <= end; port++) {
            if (IsExcludedPort(port)) continue;
            ThreadParam* p = malloc(sizeof(ThreadParam));
            if (!p) continue;
            p->port = port;
            strncpy(p->ip, ip, sizeof(p->ip) - 1);
            p->ip[sizeof(p->ip) - 1] = '\0';

            threads[active++] = CreateThread(NULL, 0, ScanPort, p, 0, NULL);
            if (active >= threadCount) {
                WaitForMultipleObjects(active, threads, TRUE, INFINITE);
                for (int i = 0; i < active; i++) CloseHandle(threads[i]);
                active = 0;
            }
        }
        token = strtok(NULL, ",");
    }

    if (active > 0) {
        WaitForMultipleObjects(active, threads, TRUE, INFINITE);
        for (int i = 0; i < active; i++) CloseHandle(threads[i]);
    }
}

int main(int argc, char** argv) {
    srand((unsigned int)time(NULL));
    SetHostnameSpoof();
    SetMacSpoof();

    if (argc < 3) return 0;

    if (argc > 3) {
        FILE* f = fopen(argv[3], "r");
        if (f) {
            fread(payloadTemplate, 1, sizeof(payloadTemplate) - 1, f);
            fclose(f);
        }
    }

    if (argc > 4) excludedPortsStr = _strdup(argv[4]);
    if (argc > 5) domainFront = _strdup(argv[5]);

    if (InitWSAContext() != 0) return 1;

    DWORD startTime = GetTickCount();
    Scan(argv[1], argv[2]);
    DWORD elapsed = GetTickCount() - startTime;

    AppendToBuffer("\n=== Scan Summary ===\n");
    AppendToBuffer("Total: %d\nOpen: %d\nClosed: %d\nTime: %.2fs\n",
        totalScanned, totalOpen, totalClosed, elapsed / 1000.0);
    printf("%s", outputBuffer);

    WSACleanup();
    if (excludedPortsStr) free(excludedPortsStr);
    if (domainFront)    free(domainFront);
    return 0;
}
