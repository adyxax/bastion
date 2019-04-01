if (SESSION_RECORDING)
    # Build libtty from the termrec project
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/termrec/)
        message("Unable to find termrec, running git submodule update --init")
        execute_process(COMMAND git submodule update --init -- termrec WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/termrec/configure)
        message("Unable to find configure file for termrec, running autogen.sh")
        execute_process(COMMAND ./autogen.sh WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/termrec)
    endif()
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/termrec/config.h)
        message("Unable to find config.h file for termrec, running configure script")
        execute_process(COMMAND ./configure WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/termrec)
    endif()
    file(GLOB_RECURSE LIBTTY_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/termrec/libtty/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/termrec/libstream/*.c)
    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/termrec/")
    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/termrec/common")
    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/termrec/libtty")
    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/termrec/sys")
    ADD_LIBRARY(libtty STATIC ${LIBTTY_SOURCES})
    SET_TARGET_PROPERTIES(libtty PROPERTIES COMPILE_FLAGS "-Wno-all -Wno-error -Wno-extra -Wno-pedantic")

    # Build termplay from the termrec project
    file(GLOB TERMPLAY_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/termrec/common/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/termrec/play/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/termrec/sys/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/termrec/sys/unix/*.c)
    add_executable(termplay ${TERMPLAY_SOURCES})
    SET_TARGET_PROPERTIES(termplay PROPERTIES COMPILE_FLAGS "-Wno-all -Wno-error -Wno-extra -Wno-pedantic")
    target_link_libraries(termplay libtty)
    target_link_libraries(termplay bz2 curl lzma pthread z)
    install(TARGETS termplay DESTINATION bin)
endif()

# Build parg library for argument parsing
add_library(libparg parg/parg.c parg/parg.h)
