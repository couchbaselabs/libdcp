FIND_PATH(LIBGIT2_INCLUDE_DIR git2.h
          HINTS
               ENV LIBGIT2_DIR
          PATH_SUFFIXES include
          PATHS
               ${DEPS_INCLUDE_DIR}
               ~/Library/Frameworks
               /Library/Frameworks
               /opt/local
               /opt)

FIND_LIBRARY(LIBGIT2
             NAMES git2
             HINTS
                 ENV LIBGIT2_DIR
             PATHS
                 ${DEPS_LIB_DIR}
                 ~/Library/Frameworks
                 /Library/Frameworks
                 /opt/local
                 /opt)
IF(NOT LIBGIT2)
  MESSAGE(FATAL_ERROR "Failed to locate libgit2")
ELSE()
  MESSAGE(STATUS "Found libgit2 headers: ${LIBGIT2_INCLUDE_DIR}")
  MESSAGE(STATUS "                  lib: ${LIBGIT2}")
ENDIF()
