include_directories("${PROJECT_SOURCE_DIR}/external/uthash/src")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
file(GLOB_RECURSE SOURCES *.c)

ADD_LIBRARY(common STATIC ${SOURCES})
