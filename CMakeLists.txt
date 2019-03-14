cmake_minimum_required (VERSION 3.0)
project (bastion LANGUAGES C VERSION 0.1)

set(CMAKE_VERBOSE_MAKEFILE FALSE)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_INSTALL_PREFIX /usr/local)

set(CMAKE_C_FLAGS "-Wall -Werror -Wextra -pedantic")
set(CMAKE_C_FLAGS_DEBUG "-g -ggdb -pg -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_MinSizeRel "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -ggdb -pg -fsanitize=address")

option(LIBSSH_VERBOSE_OUTPUT "whether or not verbose output for libssh mode is activated" OFF)
option(SESSION_RECORDING "whether or not recording feature based on lib termrec is activated" ON)

add_subdirectory(bastion)
add_subdirectory(common)
add_subdirectory(external)
