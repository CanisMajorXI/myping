# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.8

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/share/clion/bin/cmake/bin/cmake

# The command to remove a file.
RM = /usr/share/clion/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/zqw/CLionProjects/myping

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zqw/CLionProjects/myping/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/myping.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/myping.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/myping.dir/flags.make

CMakeFiles/myping.dir/main.c.o: CMakeFiles/myping.dir/flags.make
CMakeFiles/myping.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zqw/CLionProjects/myping/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/myping.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/myping.dir/main.c.o   -c /home/zqw/CLionProjects/myping/main.c

CMakeFiles/myping.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/myping.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zqw/CLionProjects/myping/main.c > CMakeFiles/myping.dir/main.c.i

CMakeFiles/myping.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/myping.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zqw/CLionProjects/myping/main.c -o CMakeFiles/myping.dir/main.c.s

CMakeFiles/myping.dir/main.c.o.requires:

.PHONY : CMakeFiles/myping.dir/main.c.o.requires

CMakeFiles/myping.dir/main.c.o.provides: CMakeFiles/myping.dir/main.c.o.requires
	$(MAKE) -f CMakeFiles/myping.dir/build.make CMakeFiles/myping.dir/main.c.o.provides.build
.PHONY : CMakeFiles/myping.dir/main.c.o.provides

CMakeFiles/myping.dir/main.c.o.provides.build: CMakeFiles/myping.dir/main.c.o


CMakeFiles/myping.dir/checksum.c.o: CMakeFiles/myping.dir/flags.make
CMakeFiles/myping.dir/checksum.c.o: checksum.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zqw/CLionProjects/myping/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/myping.dir/checksum.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/myping.dir/checksum.c.o   -c /home/zqw/CLionProjects/myping/cmake-build-debug/checksum.c

CMakeFiles/myping.dir/checksum.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/myping.dir/checksum.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zqw/CLionProjects/myping/cmake-build-debug/checksum.c > CMakeFiles/myping.dir/checksum.c.i

CMakeFiles/myping.dir/checksum.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/myping.dir/checksum.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zqw/CLionProjects/myping/cmake-build-debug/checksum.c -o CMakeFiles/myping.dir/checksum.c.s

CMakeFiles/myping.dir/checksum.c.o.requires:

.PHONY : CMakeFiles/myping.dir/checksum.c.o.requires

CMakeFiles/myping.dir/checksum.c.o.provides: CMakeFiles/myping.dir/checksum.c.o.requires
	$(MAKE) -f CMakeFiles/myping.dir/build.make CMakeFiles/myping.dir/checksum.c.o.provides.build
.PHONY : CMakeFiles/myping.dir/checksum.c.o.provides

CMakeFiles/myping.dir/checksum.c.o.provides.build: CMakeFiles/myping.dir/checksum.c.o


# Object files for target myping
myping_OBJECTS = \
"CMakeFiles/myping.dir/main.c.o" \
"CMakeFiles/myping.dir/checksum.c.o"

# External object files for target myping
myping_EXTERNAL_OBJECTS =

myping: CMakeFiles/myping.dir/main.c.o
myping: CMakeFiles/myping.dir/checksum.c.o
myping: CMakeFiles/myping.dir/build.make
myping: CMakeFiles/myping.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zqw/CLionProjects/myping/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable myping"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/myping.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/myping.dir/build: myping

.PHONY : CMakeFiles/myping.dir/build

CMakeFiles/myping.dir/requires: CMakeFiles/myping.dir/main.c.o.requires
CMakeFiles/myping.dir/requires: CMakeFiles/myping.dir/checksum.c.o.requires

.PHONY : CMakeFiles/myping.dir/requires

CMakeFiles/myping.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/myping.dir/cmake_clean.cmake
.PHONY : CMakeFiles/myping.dir/clean

CMakeFiles/myping.dir/depend:
	cd /home/zqw/CLionProjects/myping/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zqw/CLionProjects/myping /home/zqw/CLionProjects/myping /home/zqw/CLionProjects/myping/cmake-build-debug /home/zqw/CLionProjects/myping/cmake-build-debug /home/zqw/CLionProjects/myping/cmake-build-debug/CMakeFiles/myping.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/myping.dir/depend

