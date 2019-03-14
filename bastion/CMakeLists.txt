include_directories("${bastion_SOURCE_DIR}/external/termrec/libtty")
include_directories("${bastion_SOURCE_DIR}/")

file(GLOB_RECURSE SOURCES *.c)

add_executable(bastion ${SOURCES})
target_link_libraries(bastion common)
if (${SESSION_RECORDING})
    target_link_libraries(bastion libtty)
endif()
target_link_libraries(bastion bz2 lzma mysqlclient ssh z)

install (TARGETS bastion DESTINATION bin)
