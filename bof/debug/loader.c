// loader.c — a miniature BOF loader for the turn_udc2 test harness.
//
// The BOF object files reference dllimport-style symbols named
// __imp_MODULE$function (e.g. __imp_WS2_32$send) that Cobalt Strike's
// payload loader resolves via LoadLibrary/GetProcAddress. This harness
// does the same: each symbol is a plain data pointer that we fill before
// calling into the BOF.
//
// x64 only (x86 decorates stdcall imports with @N suffixes).
#include <windows.h>
#include <stdio.h>

// Storage the BOF's dllimport references bind to.
__attribute__((used)) void* __imp_WS2_32$WSAStartup;
__attribute__((used)) void* __imp_WS2_32$WSACleanup;
__attribute__((used)) void* __imp_WS2_32$WSAGetLastError;
__attribute__((used)) void* __imp_WS2_32$socket;
__attribute__((used)) void* __imp_WS2_32$connect;
__attribute__((used)) void* __imp_WS2_32$closesocket;
__attribute__((used)) void* __imp_WS2_32$send;
__attribute__((used)) void* __imp_WS2_32$recv;
__attribute__((used)) void* __imp_WS2_32$htonl;
__attribute__((used)) void* __imp_WS2_32$htons;
__attribute__((used)) void* __imp_WS2_32$ntohs;
__attribute__((used)) void* __imp_WS2_32$inet_addr;
__attribute__((used)) void* __imp_WS2_32$setsockopt;
__attribute__((used)) void* __imp_WS2_32$shutdown;
__attribute__((used)) void* __imp_WS2_32$getaddrinfo;
__attribute__((used)) void* __imp_WS2_32$freeaddrinfo;

__attribute__((used)) void* __imp_KERNEL32$GetTickCount64;
__attribute__((used)) void* __imp_KERNEL32$GetSystemTimeAsFileTime;
__attribute__((used)) void* __imp_KERNEL32$Sleep;
__attribute__((used)) void* __imp_KERNEL32$VirtualAlloc;
__attribute__((used)) void* __imp_KERNEL32$VirtualFree;

__attribute__((used)) void* __imp_BCRYPT$BCryptOpenAlgorithmProvider;
__attribute__((used)) void* __imp_BCRYPT$BCryptCloseAlgorithmProvider;
__attribute__((used)) void* __imp_BCRYPT$BCryptCreateHash;
__attribute__((used)) void* __imp_BCRYPT$BCryptDestroyHash;
__attribute__((used)) void* __imp_BCRYPT$BCryptHashData;
__attribute__((used)) void* __imp_BCRYPT$BCryptFinishHash;
__attribute__((used)) void* __imp_BCRYPT$BCryptGenRandom;

__attribute__((used)) void* __imp_SECUR32$AcquireCredentialsHandleA;
__attribute__((used)) void* __imp_SECUR32$FreeCredentialsHandle;
__attribute__((used)) void* __imp_SECUR32$InitializeSecurityContextA;
__attribute__((used)) void* __imp_SECUR32$DeleteSecurityContext;
__attribute__((used)) void* __imp_SECUR32$QueryContextAttributesA;
__attribute__((used)) void* __imp_SECUR32$EncryptMessage;
__attribute__((used)) void* __imp_SECUR32$DecryptMessage;
__attribute__((used)) void* __imp_SECUR32$FreeContextBuffer;

static struct {
    void** slot;
    const char* dll;
    const char* fn;
} gImports[] = {
    {&__imp_WS2_32$WSAStartup, "ws2_32.dll", "WSAStartup"},
    {&__imp_WS2_32$WSACleanup, "ws2_32.dll", "WSACleanup"},
    {&__imp_WS2_32$WSAGetLastError, "ws2_32.dll", "WSAGetLastError"},
    {&__imp_WS2_32$socket, "ws2_32.dll", "socket"},
    {&__imp_WS2_32$connect, "ws2_32.dll", "connect"},
    {&__imp_WS2_32$closesocket, "ws2_32.dll", "closesocket"},
    {&__imp_WS2_32$send, "ws2_32.dll", "send"},
    {&__imp_WS2_32$recv, "ws2_32.dll", "recv"},
    {&__imp_WS2_32$htonl, "ws2_32.dll", "htonl"},
    {&__imp_WS2_32$htons, "ws2_32.dll", "htons"},
    {&__imp_WS2_32$ntohs, "ws2_32.dll", "ntohs"},
    {&__imp_WS2_32$inet_addr, "ws2_32.dll", "inet_addr"},
    {&__imp_WS2_32$setsockopt, "ws2_32.dll", "setsockopt"},
    {&__imp_WS2_32$shutdown, "ws2_32.dll", "shutdown"},
    {&__imp_WS2_32$getaddrinfo, "ws2_32.dll", "getaddrinfo"},
    {&__imp_WS2_32$freeaddrinfo, "ws2_32.dll", "freeaddrinfo"},

    {&__imp_KERNEL32$GetTickCount64, "kernel32.dll", "GetTickCount64"},
    {&__imp_KERNEL32$GetSystemTimeAsFileTime, "kernel32.dll", "GetSystemTimeAsFileTime"},
    {&__imp_KERNEL32$Sleep, "kernel32.dll", "Sleep"},
    {&__imp_KERNEL32$VirtualAlloc, "kernel32.dll", "VirtualAlloc"},
    {&__imp_KERNEL32$VirtualFree, "kernel32.dll", "VirtualFree"},

    {&__imp_BCRYPT$BCryptOpenAlgorithmProvider, "bcrypt.dll", "BCryptOpenAlgorithmProvider"},
    {&__imp_BCRYPT$BCryptCloseAlgorithmProvider, "bcrypt.dll", "BCryptCloseAlgorithmProvider"},
    {&__imp_BCRYPT$BCryptCreateHash, "bcrypt.dll", "BCryptCreateHash"},
    {&__imp_BCRYPT$BCryptDestroyHash, "bcrypt.dll", "BCryptDestroyHash"},
    {&__imp_BCRYPT$BCryptHashData, "bcrypt.dll", "BCryptHashData"},
    {&__imp_BCRYPT$BCryptFinishHash, "bcrypt.dll", "BCryptFinishHash"},
    {&__imp_BCRYPT$BCryptGenRandom, "bcrypt.dll", "BCryptGenRandom"},

    {&__imp_SECUR32$AcquireCredentialsHandleA, "secur32.dll", "AcquireCredentialsHandleA"},
    {&__imp_SECUR32$FreeCredentialsHandle, "secur32.dll", "FreeCredentialsHandle"},
    {&__imp_SECUR32$InitializeSecurityContextA, "secur32.dll", "InitializeSecurityContextA"},
    {&__imp_SECUR32$DeleteSecurityContext, "secur32.dll", "DeleteSecurityContext"},
    {&__imp_SECUR32$QueryContextAttributesA, "secur32.dll", "QueryContextAttributesA"},
    {&__imp_SECUR32$EncryptMessage, "secur32.dll", "EncryptMessage"},
    {&__imp_SECUR32$DecryptMessage, "secur32.dll", "DecryptMessage"},
    {&__imp_SECUR32$FreeContextBuffer, "secur32.dll", "FreeContextBuffer"},
};

// loader_init resolves every BOF import; returns 1 on success and prints
// the first failure otherwise.
int loader_init(void) {
    size_t i;
    for (i = 0; i < sizeof(gImports) / sizeof(gImports[0]); i++) {
        HMODULE dll = LoadLibraryA(gImports[i].dll);
        if (!dll) {
            fprintf(stderr, "[-] LoadLibrary(%s) failed\n", gImports[i].dll);
            return 0;
        }
        *gImports[i].slot = (void*)GetProcAddress(dll, gImports[i].fn);
        if (!*gImports[i].slot) {
            fprintf(stderr, "[-] GetProcAddress(%s, %s) failed\n", gImports[i].dll, gImports[i].fn);
            return 0;
        }
    }
    return 1;
}
