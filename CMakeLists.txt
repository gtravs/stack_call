cmake_minimum_required(VERSION 3.27)
project(stack_call)

# 设置编译器
set(CMAKE_C_COMPILER gcc)
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
enable_language(ASM_NASM)

add_compile_options(-Os -fno-asynchronous-unwind-tables  -fno-ident -ffunction-sections -fPIC -masm=intel -Wall   -w -s  -fno-ident)
# 源文件列表
set(ASM_SRC asm/WorkCallback.asm)
set(C_SRC stack_call.c
        includes/PEB.h
        utils.c
        includes/utils.h
        includes/projstructs.h
        peb_api.c
        includes/peb_api.h)
# 生成的目标文件
set(TARGET stackcall)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE bin)

# 添加可执行文件，但只包含 C 文件
add_executable(${TARGET} ${C_SRC})

## 将 NASM 编译成目标文件
#add_custom_command(
#        OUTPUT ${CMAKE_BINARY_DIR}/bin/WorkCallback.obj
#        COMMAND nasm -f win64 -o ${CMAKE_BINARY_DIR}/bin/WorkCallback.obj ${CMAKE_SOURCE_DIR}/asm/WorkCallback.asm
#        DEPENDS ${CMAKE_SOURCE_DIR}/asm/WorkCallback.asm
#        COMMENT "Assembling NASM source"
#)
#
## 添加自定义目标，编译汇编文件
#add_custom_target(assemble_nasm ALL
#        DEPENDS ${CMAKE_BINARY_DIR}/bin/WorkCallback.obj
#)

# 将生成的目标文件添加到可执行文件中
target_link_libraries(${TARGET})

# 设置输出文件名和路径
set_target_properties(${TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        OUTPUT_NAME ${TARGET}
)

## 让可执行文件依赖于汇编目标
#add_dependencies(${TARGET} assemble_nasm)

set_target_properties(stackcall PROPERTIES LINK_FLAGS "-nostartfiles -Wl,-eSetup  -lkernel32 -luser32 ")

# 自定义清理目标
add_custom_target(custom_clean
        COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_BINARY_DIR}/bin/${TARGET}.exe
        COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_BINARY_DIR}/bin/WorkCallback.obj
        COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_BINARY_DIR}/CMakeFiles/${TARGET}.dir/${C_SRC}.obj
        COMMENT "Cleaning up..."
)