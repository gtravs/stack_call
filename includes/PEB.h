//
// Created by Jm on 2024/6/21.
//

#ifndef STACK_CALL_PEB_H
#define STACK_CALL_PEB_H
#include <windows.h>



typedef const UNICODE_STRING *PCUNICODE_STRING;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;                 //    +0x000
    LIST_ENTRY InMemoryOrderModuleList;          //    +0x010
    LIST_ENTRY InInitializationOrderModuleList;  //    +0x020
    PVOID  DllBase;                               //    +0x030
    PVOID  EntryPoint;                            //    +0x038
    ULONG_PTR  SizeOfImage;                           //    +0x040
    UNICODE_STRING FullDllName;                  //    +0x048
    UNICODE_STRING BaseDllName;                  //    +0x058
    PVOID  Flags;                                 //    +0x068
    LIST_ENTRY HashTableEntry;                   //    +0x070
    PVOID  TimeDateStamp;                         //    +0x080
    PVOID  EntryPointActivationContext;           //    +0x088
    PVOID  Lock;                                  //    +0x090
    PVOID  DdagNode;                              //    +0x098
    LIST_ENTRY NodeModuleLink;                   //    +0x0a0
    PVOID  LoadContext;                           //    +0x0b0
    PVOID  ParentDllBase;                         //    +0x0b8
    PVOID  SwitchBackContext;                     //    +0x0c0
    LIST_ENTRY BaseAddressIndexNode1;            //    +0x0c8
    PVOID  BaseAddressIndexNode3;                 //    +0x0d8
    PVOID  MappingInfoIndexNode1;                 //    +0x0e0
    PVOID  MappingInfoIndexNode2;                 //    +0x0e8
    PVOID  MappingInfoIndexNode3;                 //    +0x0f0
    PVOID  OriginalBase;                          //    +0x0f8
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    PVOID  lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID  lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    PVOID  lpMutant;
    PVOID  lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    PVOID  lpProcessParameters;
    PVOID  lpSubSystemData;
    PVOID  lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    PVOID  lpFastPebLockRoutine;
    PVOID  lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    PVOID  lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    PVOID  lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    PVOID  lpReadOnlySharedMemoryBase;
    PVOID  lpReadOnlySharedMemoryHeap;
    PVOID  lpReadOnlyStaticServerData;
    PVOID  lpAnsiCodePageData;
    PVOID  lpOemCodePageData;
    PVOID  lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    PVOID  lpProcessHeaps;
    PVOID  lpGdiSharedHandleTable;
    PVOID  lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    PVOID  lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    PVOID  lpPostProcessInitRoutine;
    PVOID  lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    PVOID  lppShimData;
    PVOID  lpAppCompatInfo;
    UNICODE_STRING usCSDVersion;
    PVOID  lpActivationContextData;
    PVOID  lpProcessAssemblyStorageMap;
    PVOID  lpSystemDefaultActivationContextData;
    PVOID  lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * PPEB;
#endif //STACK_CALL_PEB_H
