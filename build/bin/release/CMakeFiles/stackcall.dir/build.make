# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.27

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = V:\App\CLion\bin\cmake\win\x64\bin\cmake.exe

# The command to remove a file.
RM = V:\App\CLion\bin\cmake\win\x64\bin\cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = S:\Code\C_++\PayloadCode\proxy_call_shellcode

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release

# Include any dependencies generated for this target.
include CMakeFiles/stackcall.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/stackcall.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/stackcall.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/stackcall.dir/flags.make

CMakeFiles/stackcall.dir/stack_call.c.obj: CMakeFiles/stackcall.dir/flags.make
CMakeFiles/stackcall.dir/stack_call.c.obj: S:/Code/C_++/PayloadCode/proxy_call_shellcode/stack_call.c
CMakeFiles/stackcall.dir/stack_call.c.obj: CMakeFiles/stackcall.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/stackcall.dir/stack_call.c.obj"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/stackcall.dir/stack_call.c.obj -MF CMakeFiles\stackcall.dir\stack_call.c.obj.d -o CMakeFiles\stackcall.dir\stack_call.c.obj -c S:\Code\C_++\PayloadCode\proxy_call_shellcode\stack_call.c

CMakeFiles/stackcall.dir/stack_call.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/stackcall.dir/stack_call.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E S:\Code\C_++\PayloadCode\proxy_call_shellcode\stack_call.c > CMakeFiles\stackcall.dir\stack_call.c.i

CMakeFiles/stackcall.dir/stack_call.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/stackcall.dir/stack_call.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S S:\Code\C_++\PayloadCode\proxy_call_shellcode\stack_call.c -o CMakeFiles\stackcall.dir\stack_call.c.s

CMakeFiles/stackcall.dir/utils.c.obj: CMakeFiles/stackcall.dir/flags.make
CMakeFiles/stackcall.dir/utils.c.obj: S:/Code/C_++/PayloadCode/proxy_call_shellcode/utils.c
CMakeFiles/stackcall.dir/utils.c.obj: CMakeFiles/stackcall.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/stackcall.dir/utils.c.obj"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/stackcall.dir/utils.c.obj -MF CMakeFiles\stackcall.dir\utils.c.obj.d -o CMakeFiles\stackcall.dir\utils.c.obj -c S:\Code\C_++\PayloadCode\proxy_call_shellcode\utils.c

CMakeFiles/stackcall.dir/utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/stackcall.dir/utils.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E S:\Code\C_++\PayloadCode\proxy_call_shellcode\utils.c > CMakeFiles\stackcall.dir\utils.c.i

CMakeFiles/stackcall.dir/utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/stackcall.dir/utils.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S S:\Code\C_++\PayloadCode\proxy_call_shellcode\utils.c -o CMakeFiles\stackcall.dir\utils.c.s

CMakeFiles/stackcall.dir/peb_api.c.obj: CMakeFiles/stackcall.dir/flags.make
CMakeFiles/stackcall.dir/peb_api.c.obj: S:/Code/C_++/PayloadCode/proxy_call_shellcode/peb_api.c
CMakeFiles/stackcall.dir/peb_api.c.obj: CMakeFiles/stackcall.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/stackcall.dir/peb_api.c.obj"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/stackcall.dir/peb_api.c.obj -MF CMakeFiles\stackcall.dir\peb_api.c.obj.d -o CMakeFiles\stackcall.dir\peb_api.c.obj -c S:\Code\C_++\PayloadCode\proxy_call_shellcode\peb_api.c

CMakeFiles/stackcall.dir/peb_api.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/stackcall.dir/peb_api.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E S:\Code\C_++\PayloadCode\proxy_call_shellcode\peb_api.c > CMakeFiles\stackcall.dir\peb_api.c.i

CMakeFiles/stackcall.dir/peb_api.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/stackcall.dir/peb_api.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S S:\Code\C_++\PayloadCode\proxy_call_shellcode\peb_api.c -o CMakeFiles\stackcall.dir\peb_api.c.s

# Object files for target stackcall
stackcall_OBJECTS = \
"CMakeFiles/stackcall.dir/stack_call.c.obj" \
"CMakeFiles/stackcall.dir/utils.c.obj" \
"CMakeFiles/stackcall.dir/peb_api.c.obj"

# External object files for target stackcall
stackcall_EXTERNAL_OBJECTS =

bin/stackcall.exe: CMakeFiles/stackcall.dir/stack_call.c.obj
bin/stackcall.exe: CMakeFiles/stackcall.dir/utils.c.obj
bin/stackcall.exe: CMakeFiles/stackcall.dir/peb_api.c.obj
bin/stackcall.exe: CMakeFiles/stackcall.dir/build.make
bin/stackcall.exe: CMakeFiles/stackcall.dir/linkLibs.rsp
bin/stackcall.exe: CMakeFiles/stackcall.dir/objects1.rsp
bin/stackcall.exe: CMakeFiles/stackcall.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable bin\stackcall.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\stackcall.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/stackcall.dir/build: bin/stackcall.exe
.PHONY : CMakeFiles/stackcall.dir/build

CMakeFiles/stackcall.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\stackcall.dir\cmake_clean.cmake
.PHONY : CMakeFiles/stackcall.dir/clean

CMakeFiles/stackcall.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" S:\Code\C_++\PayloadCode\proxy_call_shellcode S:\Code\C_++\PayloadCode\proxy_call_shellcode S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release S:\Code\C_++\PayloadCode\proxy_call_shellcode\build\bin\release\CMakeFiles\stackcall.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/stackcall.dir/depend

