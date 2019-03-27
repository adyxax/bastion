include_directories("${PROJECT_SOURCE_DIR}/external/termrec/libtty")

file(GLOB_RECURSE SOURCES *.c)

add_executable(bastion ${SOURCES})
target_link_libraries(bastion common)
if (${SESSION_RECORDING})
    target_link_libraries(bastion libtty)
endif()
target_link_libraries(bastion bz2 config lzma mysqlclient ssh z)

install(TARGETS bastion DESTINATION bin)

configure_file("bastion.conf.example.in" "bastion.conf.example")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/bastion.conf.example" DESTINATION etc/bastion)
install(DIRECTORY DESTINATION var/log/bastion)
