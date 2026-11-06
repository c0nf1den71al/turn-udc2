// dfr.h — dynamic function resolution for a CRT-less BOF.
//
// Beacon's BOF loader resolves symbols named MODULE$function by
// LoadLibrary/GetProcAddress at load time. We declare each import with
// its real signature and alias the plain name to the decorated one.
//
// All headers are included here; translation units must include dfr.h
// last so the aliases do not affect the system declarations.
#ifndef DFR_H
#define DFR_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>
#include <bcrypt.h>

// ---------------------------------------------------------------- ws2_32
__declspec(dllimport) int __stdcall WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
__declspec(dllimport) int __stdcall WS2_32$WSACleanup(void);
__declspec(dllimport) SOCKET __stdcall WS2_32$socket(int af, int type, int protocol);
__declspec(dllimport) int __stdcall WS2_32$connect(SOCKET s, const struct sockaddr* name, int namelen);
__declspec(dllimport) int __stdcall WS2_32$closesocket(SOCKET s);
__declspec(dllimport) int __stdcall WS2_32$send(SOCKET s, const char* buf, int len, int flags);
__declspec(dllimport) int __stdcall WS2_32$recv(SOCKET s, char* buf, int len, int flags);
__declspec(dllimport) u_long __stdcall WS2_32$htonl(u_long hostlong);
__declspec(dllimport) u_short __stdcall WS2_32$htons(u_short hostshort);
__declspec(dllimport) u_short __stdcall WS2_32$ntohs(u_short netshort);
__declspec(dllimport) unsigned long __stdcall WS2_32$inet_addr(const char* cp);
__declspec(dllimport) int __stdcall WS2_32$setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen);
__declspec(dllimport) int __stdcall WS2_32$shutdown(SOCKET s, int how);
__declspec(dllimport) int __stdcall WS2_32$getaddrinfo(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res);
__declspec(dllimport) void __stdcall WS2_32$freeaddrinfo(struct addrinfo* ai);
__declspec(dllimport) int __stdcall WS2_32$WSAGetLastError(void);

#define WSAStartup WS2_32$WSAStartup
#define WSACleanup WS2_32$WSACleanup
#define socket WS2_32$socket
#define connect WS2_32$connect
#define closesocket WS2_32$closesocket
#define send WS2_32$send
#define recv WS2_32$recv
#define htonl WS2_32$htonl
#define htons WS2_32$htons
#define ntohs WS2_32$ntohs
#define inet_addr WS2_32$inet_addr
#define setsockopt WS2_32$setsockopt
#define shutdown WS2_32$shutdown
#define getaddrinfo WS2_32$getaddrinfo
#define freeaddrinfo WS2_32$freeaddrinfo
#define WSAGetLastError WS2_32$WSAGetLastError

// -------------------------------------------------------------- kernel32
__declspec(dllimport) ULONGLONG __stdcall KERNEL32$GetTickCount64(void);
__declspec(dllimport) void __stdcall KERNEL32$GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
__declspec(dllimport) void __stdcall KERNEL32$Sleep(DWORD dwMilliseconds);
__declspec(dllimport) LPVOID __stdcall KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
__declspec(dllimport) BOOL __stdcall KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

#define GetTickCount64 KERNEL32$GetTickCount64
#define GetSystemTimeAsFileTime KERNEL32$GetSystemTimeAsFileTime
#define Sleep KERNEL32$Sleep
#define VirtualAlloc KERNEL32$VirtualAlloc
#define VirtualFree KERNEL32$VirtualFree

// ---------------------------------------------------------------- bcrypt
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
__declspec(dllimport) NTSTATUS __stdcall BCRYPT$BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);

#define BCryptOpenAlgorithmProvider BCRYPT$BCryptOpenAlgorithmProvider
#define BCryptCloseAlgorithmProvider BCRYPT$BCryptCloseAlgorithmProvider
#define BCryptCreateHash BCRYPT$BCryptCreateHash
#define BCryptDestroyHash BCRYPT$BCryptDestroyHash
#define BCryptHashData BCRYPT$BCryptHashData
#define BCryptFinishHash BCRYPT$BCryptFinishHash
#define BCryptGenRandom BCRYPT$BCryptGenRandom

// --------------------------------------------------------------- secur32
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$AcquireCredentialsHandleA(SEC_CHAR* pszPrincipal, SEC_CHAR* pszPackage, ULONG fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$InitializeSecurityContextA(PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG* pfContextAttr, PTimeStamp ptsExpiry);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$DeleteSecurityContext(PCtxtHandle phContext);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$QueryContextAttributesA(PCtxtHandle phContext, ULONG ulAttribute, void* pBuffer);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, ULONG* pfQOP);
__declspec(dllimport) SECURITY_STATUS __stdcall SECUR32$FreeContextBuffer(PVOID pvContextBuffer);

#define AcquireCredentialsHandleA SECUR32$AcquireCredentialsHandleA
#define FreeCredentialsHandle SECUR32$FreeCredentialsHandle
#define InitializeSecurityContextA SECUR32$InitializeSecurityContextA
#define DeleteSecurityContext SECUR32$DeleteSecurityContext
#define QueryContextAttributesA SECUR32$QueryContextAttributesA
#define EncryptMessage SECUR32$EncryptMessage
#define DecryptMessage SECUR32$DecryptMessage
#define FreeContextBuffer SECUR32$FreeContextBuffer

#endif // DFR_H
