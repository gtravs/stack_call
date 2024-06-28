//
// Created by Jm on 2024/6/21.
//

#ifndef STACK_CALL_UTILS_H
#define STACK_CALL_UTILS_H
#include <Windows.h>

void stomp(ULONG_PTR length, BYTE * buff);
void utf16_to_utf8(wchar_t * wide_string, DWORD wide_string_len, BYTE * ascii_string);
DWORD hash_ascii_string(BYTE* utf8_string);
BOOL MemoryCompare(BYTE* memory_A, BYTE* memory_B, DWORD memory_size);
void* FindGadget(BYTE* module_section_addr, DWORD module_section_size, BYTE* gadget, DWORD gadget_size);
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase);
void * CalculateFunctionStackSizeWrapper(BYTE * ReturnAddress, APIS * api);
BYTE * find_api_return_address_on_stack(RUNTIME_FUNCTION* api_runtime_function, BYTE * api_virtual_address);
RUNTIME_FUNCTION* get_runtime_function_entry_for_api( Dll * module, BYTE* api_address);
VOID memory_copy(PVOID destination_ptr, PVOID source_ptr, DWORD number_of_bytes);
SIZE_T StringLengthA(LPCSTR String);
#endif //STACK_CALL_UTILS_H
