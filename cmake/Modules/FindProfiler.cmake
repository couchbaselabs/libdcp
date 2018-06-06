FIND_LIBRARY(LIBPROFILER
             NAMES profiler
             HINTS
                 ENV LIBPROFILER_DIR
             PATHS
                 ${DEPS_LIB_DIR}
                 ~/Library/Frameworks
                 /Library/Frameworks
                 /opt/local
                 /opt)

IF(LIBPROFILER)
  MESSAGE(STATUS "Found libprofiler: ${LIBPROFILER}")
ENDIF()
