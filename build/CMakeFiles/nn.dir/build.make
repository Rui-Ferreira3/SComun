# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/uni/SComun

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/uni/SComun/build

# Include any dependencies generated for this target.
include CMakeFiles/nn.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/nn.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/nn.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/nn.dir/flags.make

CMakeFiles/nn.dir/nn.cpp.o: CMakeFiles/nn.dir/flags.make
CMakeFiles/nn.dir/nn.cpp.o: ../nn.cpp
CMakeFiles/nn.dir/nn.cpp.o: CMakeFiles/nn.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/uni/SComun/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/nn.dir/nn.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/nn.dir/nn.cpp.o -MF CMakeFiles/nn.dir/nn.cpp.o.d -o CMakeFiles/nn.dir/nn.cpp.o -c /root/uni/SComun/nn.cpp

CMakeFiles/nn.dir/nn.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/nn.dir/nn.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/uni/SComun/nn.cpp > CMakeFiles/nn.dir/nn.cpp.i

CMakeFiles/nn.dir/nn.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/nn.dir/nn.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/uni/SComun/nn.cpp -o CMakeFiles/nn.dir/nn.cpp.s

# Object files for target nn
nn_OBJECTS = \
"CMakeFiles/nn.dir/nn.cpp.o"

# External object files for target nn
nn_EXTERNAL_OBJECTS =

nn: CMakeFiles/nn.dir/nn.cpp.o
nn: CMakeFiles/nn.dir/build.make
nn: /usr/local/lib/libOPENFHEpke.so.1.0.3
nn: /usr/local/lib/libOPENFHEbinfhe.so.1.0.3
nn: /usr/local/lib/libOPENFHEcore.so.1.0.3
nn: CMakeFiles/nn.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/uni/SComun/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable nn"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/nn.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/nn.dir/build: nn
.PHONY : CMakeFiles/nn.dir/build

CMakeFiles/nn.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/nn.dir/cmake_clean.cmake
.PHONY : CMakeFiles/nn.dir/clean

CMakeFiles/nn.dir/depend:
	cd /root/uni/SComun/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/uni/SComun /root/uni/SComun /root/uni/SComun/build /root/uni/SComun/build /root/uni/SComun/build/CMakeFiles/nn.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/nn.dir/depend
