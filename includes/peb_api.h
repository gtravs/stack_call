//
// Created by Jm on 2024/6/21.
//

#ifndef STACK_CALL_PEB_API_H
#define STACK_CALL_PEB_API_H
BYTE * loaded_module_base_from_hash(DWORD hash);
void * resolve_api_address_from_hash(DWORD api_hash, Dll * module);
#define NtCurrentProcess() ( (PVOID)(LONG_PTR) -1 )
extern PVOID  NTAPI spoof_synthetic_callstack(PVOID  a, ...);
void getApis(APIS * api);
void * xGetProcAddress_hash(DWORD api_hash, Dll * module);
void * xLoadLibrary(void * library_name);
void parse_module_headers(Dll* module);
#endif //STACK_CALL_PEB_API_H
