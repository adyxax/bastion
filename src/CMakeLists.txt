include_directories("${bastion_SOURCE_DIR}/termrec/libtty/")

file(GLOB_RECURSE SOURCES *.c)

add_executable(bastion ${SOURCES})
add_library(libtty.a STATIC IMPORTED)
set_property(TARGET libtty.a PROPERTY IMPORTED_LOCATION "${bastion_SOURCE_DIR}/libtty.a")
target_link_libraries(bastion libtty.a)
target_link_libraries(bastion bz2 curl lzma mysqlclient pthread ssh z)
