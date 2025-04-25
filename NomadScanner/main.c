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
        } else {
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
    SetComputerNameA("CORP-WINPC01");
}

void SetMacSpoof() {
    // Stub — requires driver-level tools or registry patch with reboot
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
    struct addrinfo hints, *res = NULL;
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

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s);
        freeaddrinfo(res);
        return FALSE;
    }

    const char* method = http_methods[rand() % (sizeof(http_methods) / sizeof(http_methods[0]))];
    const char* ua_plain = user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))];
    char ua[256];
    strncpy(ua, ua_plain, sizeof(ua) - 1);
    ua[sizeof(ua) - 1] = '\0';

    const char* host_plain = domainFront ? domainFront : ip;
    char host[256];
    strncpy(host, host_plain, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    char message[1024];
    if (strlen(payloadTemplate) > 0) {
        snprintf(message, sizeof(message), payloadTemplate, ip, port, ua);
    } else {
        snprintf(message, sizeof(message), "%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", method, host, ua);
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
    DWORD port = *(DWORD*)param;
    CHAR ip[128];
    strncpy(ip, (CHAR*)((char*)param + sizeof(DWORD)), 127);
    ip[127] = '\0';
    InterlockedIncrement((volatile LONG*)&totalScanned);

    if (IsAlive(ip, port)) {
        InterlockedIncrement((volatile LONG*)&totalOpen);
        AppendToBuffer("[+] %s:%lu is open\n", ip, port);
    } else {
        InterlockedIncrement((volatile LONG*)&totalClosed);
        AppendToBuffer("[-] %s:%lu is closed\n", ip, port);
    }

    Sleep(delayMin + rand() % (delayMax - delayMin));
    free(param);
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
        } else {
            start = end = atoi(token);
        }

        for (int port = start; port <= end; port++) {
            if (IsExcludedPort(port)) continue;
            DWORD* data = malloc(sizeof(DWORD) + 128);
            if (!data) continue;
            *data = port;
            strncpy((char*)(data + 1), ip, 127);
            ((char*)(data + 1))[127] = '\0';
            threads[active++] = CreateThread(NULL, 0, ScanPort, data, 0, NULL);

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
    AppendToBuffer("Total: %d\nOpen: %d\nClosed: %d\nTime: %.2fs\n", totalScanned, totalOpen, totalClosed, elapsed / 1000.0);
    MessageBoxA(NULL, outputBuffer, "Scan Results", MB_OK);

    WSACleanup();
    if (excludedPortsStr) free(excludedPortsStr);
    if (domainFront) free(domainFront);
    return 0;
}
