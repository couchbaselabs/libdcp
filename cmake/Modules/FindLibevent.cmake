FIND_PATH(LIBEVENT_INCLUDE_DIR evutil.h
          HINTS
               ENV LIBEVENT_DIR
          PATH_SUFFIXES include
          PATHS
               ${DEPS_INCLUDE_DIR}
               ~/Library/Frameworks
               /Library/Frameworks
               /opt/local
               /opt/libevent
               /opt)

FIND_LIBRARY(LIBEVENT_CORE
             NAMES event_core
             HINTS
                 ENV LIBEVENT_DIR
             PATHS
                 ${DEPS_LIB_DIR}
                 ~/Library/Frameworks
                 /Library/Frameworks
                 /opt/local
                 /opt/libevent
                 /opt)
IF(NOT LIBEVENT_CORE)
  MESSAGE(FATAL_ERROR "Failed to locate libevent event_core")
ENDIF()


FIND_LIBRARY(LIBEVENT_EXTRA
             NAMES event_extra
             HINTS
                 ENV LIBEVENT_DIR
             PATHS
                 ${DEPS_LIB_DIR}
                 ~/Library/Frameworks
                 /Library/Frameworks
                 /opt/local
                 /opt/libevent
                 /opt)
IF(NOT LIBEVENT_EXTRA)
  MESSAGE(FATAL_ERROR "Failed to locate libevent event_extra")
ENDIF()

MESSAGE(STATUS "Found libevent headers: ${LIBEVENT_INCLUDE_DIR}")
MESSAGE(STATUS "                  core: ${LIBEVENT_CORE}")
MESSAGE(STATUS "                 extra: ${LIBEVENT_EXTRA}")

SET(LIBEVENT_LIBRARIES "${LIBEVENT_CORE}")
LIST(APPEND LIBEVENT_LIBRARIES ${LIBEVENT_EXTRA})
