include_directories("${bastion_SOURCE_DIR}/external/termrec/libtty")
include_directories("${bastion_SOURCE_DIR}/")

file(GLOB_RECURSE SOURCES *.c)

add_executable(bastion ${SOURCES})
target_link_libraries(bastion libtty common)
target_link_libraries(bastion bz2 curl lzma mysqlclient pthread ssh z)
