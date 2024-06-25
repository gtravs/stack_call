#include "includes/projstructs.h"
#include "includes/PEB.h"
#include "includes/utils.h"
#include "includes/peb_api.h"

void stomp(ULONG_PTR length, BYTE * buff) {
    DWORD i;
    for (i = 0; i < length; ++i)
    {
        buff[i] = 0;
    }
}

// Havoc C2 function
SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

void utf8_string_to_lower(BYTE* utf8_string_in, BYTE* utf8_string_out)
{
    for (DWORD i = 0; utf8_string_in[i] != '\0'; i++)
    {
        if (utf8_string_in[i] >= 'A' && utf8_string_in[i] <= 'Z')
        {
            utf8_string_out[i] = utf8_string_in[i] - 'A' + 'a';
        }
        else
        {
            utf8_string_out[i] = utf8_string_in[i];
        }
    }
}


void utf16_to_utf8(wchar_t * wide_string, DWORD wide_string_len, BYTE * ascii_string)
{
    for (DWORD i = 0; i < wide_string_len; ++i)
    {
        wchar_t this_char = wide_string[i];
        * ascii_string++  = (BYTE)this_char;
    }
    * ascii_string = '\0';
}

PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt){
    volatile BYTE *vptr = (volatile BYTE *)ptr;
    __stosb ((PBYTE)((DWORD64)vptr),0,cnt);
    return ptr;
}

DWORD hash_ascii_string(BYTE* utf8_string)
{
    BYTE lower_string[256] = { 0 };
    DWORD  length = StringLengthA(utf8_string);
    utf8_string_to_lower(utf8_string, lower_string);
    BYTE prime  = 0xE3;
    BYTE seed   = 0xB0;
    BYTE offset = 0xBC;

    DWORD hash = (offset ^ seed);
    for (DWORD i = 0; i < length; ++i) {
        hash ^= (DWORD)lower_string[i];
        hash *= prime;
    }
    return hash;
}

BOOL MemoryCompare(BYTE* memory_A, BYTE* memory_B, DWORD memory_size)
{
    BYTE byte_A = 0x00;
    BYTE byte_B = 0x00;
    for (DWORD counter = 0; counter < memory_size; counter++)
    {
        byte_A = *(memory_A + counter);
        byte_B = *(memory_B + counter);
        if (byte_A != byte_B)
        {
            return FALSE;
        }
    }
    return TRUE;
}

void* FindGadget(BYTE* module_section_addr, DWORD module_section_size, BYTE* gadget, DWORD gadget_size)
{
    BYTE* this_module_byte_pointer = NULL;
    for (DWORD x = 0; x < module_section_size; x++)
    {
        this_module_byte_pointer = module_section_addr + x;
        if (MemoryCompare(this_module_byte_pointer, gadget, gadget_size))
        {
            return (void*)(this_module_byte_pointer);
        }
    };
    return NULL;
}

/* Credit to VulcanRaven project for the original implementation of these two*/
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        if (unwindOperation == UWOP_PUSH_NONVOL)
        {
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
        }
        if (unwindOperation == UWOP_SAVE_NONVOL)
        {
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
        }
        if (unwindOperation == UWOP_ALLOC_SMALL)
        {
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
        }
        if (unwindOperation == UWOP_ALLOC_LARGE)
        {
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
        }
        if (unwindOperation == UWOP_SET_FPREG)
        {
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            // printf("[-] Error: Unsupported Unwind Op Code\n");
        }
        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }
    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
    Cleanup:
    return status;
}

void * CalculateFunctionStackSizeWrapper(BYTE * ReturnAddress, APIS * api)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }
    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = api->ntdll.RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        // printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }
    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    Cleanup:
    return status;
}

// From bottom of stack --> up
BYTE * find_api_return_address_on_stack(RUNTIME_FUNCTION* api_runtime_function, BYTE * api_virtual_address)
{
    NT_TIB* tib = (NT_TIB * ) __readgsqword(0x30);
    BYTE* api_end_virtual_address = api_virtual_address + api_runtime_function->EndAddress;
    ULONG_PTR* this_stack_address = tib->StackBase - 0x30;
    do
    {
        ULONG_PTR this_stack_value = *this_stack_address;
        if (this_stack_value)
        {
            if (
                    (this_stack_value >= api_virtual_address)
                    &&
                    (this_stack_value < api_end_virtual_address)
                    )
            {
                return (BYTE* )this_stack_address;
            }
        }
        this_stack_address -= 1;
    } while (true);
    return NULL;
}

RUNTIME_FUNCTION* get_runtime_function_entry_for_api( Dll * module, BYTE* api_address)
{
    RUNTIME_FUNCTION* runtimeFunction             = NULL;
    RUNTIME_FUNCTION* this_runtime_function_entry = NULL;

    BYTE * api_offset_from_dll_base = (BYTE *) (api_address - (BYTE *) module->dllBase);
    this_runtime_function_entry = (RUNTIME_FUNCTION*)((BYTE*)module->pdata_section);

    for (DWORD i = 0; i < module->pdata_section_size / sizeof(RUNTIME_FUNCTION); i++) {
        if (
                (api_offset_from_dll_base >= this_runtime_function_entry->BeginAddress)
                &&
                (api_offset_from_dll_base  < this_runtime_function_entry->EndAddress)
                )
        {
            return this_runtime_function_entry;
            break;
        }
        this_runtime_function_entry = (RUNTIME_FUNCTION*)( (BYTE*)this_runtime_function_entry + sizeof(RUNTIME_FUNCTION));
    }
    return NULL;
}