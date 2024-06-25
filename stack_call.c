#include <Windows.h>
#include "includes/projstructs.h"
#include "includes/peb_api.h"
#include <stdio.h>

__asm__(
        ".global Setup\n"      // 声明Setup为全局符号
        "Setup:\n"
        "    push rsi\n"       // 保存rsi到栈中
        "    mov  rsi, rsp\n"  // 将rsi设置为当前栈指针
        "    and  rsp, 0xFFFFFFFFFFFFFFF0\n"    // 将栈对齐到16字节边界
        "    sub  rsp, 0x20\n" // 在栈上分配32字节空间
        "    call run\n"
        "    mov  rsp, rsi\n"  // 恢复栈指针
        "    pop  rsi\n"       // 恢复rsi的原始值
        "    pop  rcx\n"       // 将返回地址放入rcx
        "    add  rsp, 0x20\n" // 移除栈上的32字节空间
        "    and  rsp, 0xFFFFFFFFFFFFFFF0\n"    // 将栈对齐到16字节边界
        "    jmp  rcx\n"
        );

const char user32_name[] __attribute__((section(".text"))) = "User32.dll";
const char wininet_name[] __attribute__((section(".text"))) = "wininet.dll";
const char test_name[]  __attribute__((section(".text"))) = "test";

UINT_PTR getLoadLibraryA() {
    UINT_PTR xLoadLibraryAddr;
    __asm__(
            "lea rax, [rip + xLoadLibrary]\n\t"
            "mov %0, rax\n\t"
            : "=r" (xLoadLibraryAddr)
            );
    return xLoadLibraryAddr;
}

void WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    __asm__  (
            "mov rcx, rdx\n\t"            // 将 rdx 的值移到 rcx
            "xor rdx, rdx\n\t"            // 将 rdx 置零
            "call getLoadLibraryA\n\t"    // 调用 getLoadLibraryA 函数
            "jmp rax\n\t"                 // 跳转到 rax 中的地址
            );
}

void loadLibrary(void * lib_name) {
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


void run() {
    loadLibrary(wininet_name);
    Dll wininet = {0};
    wininet.dllBase =  loaded_module_base_from_hash(WININET);
    parse_module_headers(&wininet);
    if (wininet.dllBase != NULL) {
        loadLibrary(user32_name);
        Dll user32 = {0};
        user32.dllBase = loaded_module_base_from_hash(USER32);
        parse_module_headers(&user32);
        tMessageBoxA  MessageBoxA = (tMessageBoxA) xGetProcAddress_hash(MESSAGEBOXA,&user32);
        MessageBoxA(0,test_name,test_name,MB_OK);
    }
}