cmake_minimum_required (VERSION 3.0)
project (bastion LANGUAGES C VERSION 0.1)

set(CMAKE_VERBOSE_MAKEFILE FALSE)
set(CMAKE_BUILD_TYPE DEBUG)

set(CMAKE_C_FLAGS "-Wall -Werror -Wextra -pedantic")
set(CMAKE_C_FLAGS_DEBUG "-g -ggdb -pg -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Os -g")

option(LIBSSH_VERBOSE_OUTPOUT "whether or not verbose output for libssh mode is activated" OFF)

add_subdirectory(src)
