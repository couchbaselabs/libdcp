# Gets the libdcp version
# Sets:
#  LDCP_VERSION: Version string
#  LDCP_CHANGESET: SCM Revision number
#  LDCP_VERSION_HEX Numeric hex version
#  LDCP_VERSION_MAJOR
#  LDCP_VERSION_MINOR
#  LDCP_VERSION_PATCH

## Try git first ##
FIND_PROGRAM(GIT_EXECUTABLE NAMES git git.exe)
MACRO(RUNGIT outvar)
  EXECUTE_PROCESS(COMMAND git ${ARGN}
    OUTPUT_VARIABLE ${outvar}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE)
ENDMACRO()

if (GIT_EXECUTABLE)
  RUNGIT(LDCP_REVDESCRIBE describe --long)
  RUNGIT(LDCP_VERSION describe)
  STRING(REPLACE "-" "_" LDCP_VERSION "${LDCP_VERSION}")
  MESSAGE(STATUS "Sanitized VERSION=${LDCP_VERSION}")
  RUNGIT(LDCP_VERSION_CHANGESET rev-parse HEAD)

  EXECUTE_PROCESS(
    COMMAND echo ${LDCP_VERSION}
    COMMAND awk -F. "{printf \"0x%0.2d%0.2d%0.2d\", $1, $2, $3}"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    OUTPUT_VARIABLE LDCP_VERSION_HEX)
ENDIF()

IF(LDCP_VERSION)
  # Have the version information
  CONFIGURE_FILE(${LDCP_GENINFODIR}/distinfo.cmake.in ${LDCP_GENINFODIR}/distinfo.cmake)
ENDIF()

# library version
IF(NOT LDCP_VERSION AND EXISTS ${LDCP_GENINFODIR}/distinfo.cmake)
  INCLUDE(${LDCP_GENINFODIR}/distinfo.cmake)
ENDIF()

IF (NOT LDCP_VERSION)
  SET(LDCP_NOGITVERSION ON)
  SET(LDCP_VERSION "0.1.0")
ENDIF()
IF (NOT LDCP_VERSION_CHANGESET)
  SET(LDCP_VERSION_CHANGESET "0xdeadbeef")
ENDIF()
IF (NOT LDCP_VERSION_HEX)
  SET(LDCP_VERSION_HEX 0x000100)
ENDIF()

# Now parse the version string
STRING(REPLACE "." ";" LDCP_VERSION_LIST "${LDCP_VERSION}")
LIST(GET LDCP_VERSION_LIST 0 LDCP_VERSION_MAJOR)
LIST(GET LDCP_VERSION_LIST 1 LDCP_VERSION_MINOR)
LIST(GET LDCP_VERSION_LIST 2 LDCP_VERSION_PATCH)

# Determine the SONAME for the library
SET(LDCP_SONAME_FULL "${LDCP_VERSION_MAJOR}.${LDCP_VERSION_MINOR}.${LDCP_VERSION_PATCH}")

MESSAGE(STATUS "libdcp ${LDCP_VERSION_MAJOR},${LDCP_VERSION_MINOR},${LDCP_VERSION_PATCH}")
MESSAGE(STATUS "Building libdcp ${LDCP_VERSION}/${LDCP_VERSION_CHANGESET}")