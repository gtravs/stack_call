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
CMAKE_SOURCE_DIR = S:\Code\C_++\Tmp\stack_call

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = S:\Code\C_++\Tmp\stack_call\build\bin\release

# Utility rule file for custom_clean.

# Include any custom commands dependencies for this target.
include CMakeFiles/custom_clean.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/custom_clean.dir/progress.make

CMakeFiles/custom_clean:
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=S:\Code\C_++\Tmp\stack_call\build\bin\release\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Cleaning up..."
	V:\App\CLion\bin\cmake\win\x64\bin\cmake.exe -E remove -f S:/Code/C_++/Tmp/stack_call/build/bin/release/bin/stackcall.exe
	V:\App\CLion\bin\cmake\win\x64\bin\cmake.exe -E remove -f S:/Code/C_++/Tmp/stack_call/build/bin/release/bin/WorkCallback.obj
	V:\App\CLion\bin\cmake\win\x64\bin\cmake.exe -E remove -f S:/Code/C_++/Tmp/stack_call/build/bin/release/CMakeFiles/stackcall.dir/stack_call.c includes/PEB.h utils.c includes/utils.h includes/projstructs.h peb_api.c includes/peb_api.h.obj

custom_clean: CMakeFiles/custom_clean
custom_clean: CMakeFiles/custom_clean.dir/build.make
.PHONY : custom_clean

# Rule to build all files generated by this target.
CMakeFiles/custom_clean.dir/build: custom_clean
.PHONY : CMakeFiles/custom_clean.dir/build

CMakeFiles/custom_clean.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\custom_clean.dir\cmake_clean.cmake
.PHONY : CMakeFiles/custom_clean.dir/clean

CMakeFiles/custom_clean.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" S:\Code\C_++\Tmp\stack_call S:\Code\C_++\Tmp\stack_call S:\Code\C_++\Tmp\stack_call\build\bin\release S:\Code\C_++\Tmp\stack_call\build\bin\release S:\Code\C_++\Tmp\stack_call\build\bin\release\CMakeFiles\custom_clean.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/custom_clean.dir/depend

