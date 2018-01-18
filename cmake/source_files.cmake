# These define the various source file listings of various modules
# within the library.
# This is included by the top-level CMakeLists.txt

FILE(GLOB LDCP_CORE_SRC src/*.c)

FILE(GLOB LDCP_TOOLS_SRC tools/*.c)

SET(CONTRIB_CJSON_SRC ${SOURCE_ROOT}/contrib/cJSON/cJSON.c)
