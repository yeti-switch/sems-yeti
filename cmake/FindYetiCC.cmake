#.rst:
# FindYetiCC
# --------
#
# Find libyeticc
#
# Find libyeticc headers and libraries.
#
# ::
#
#   YETICC_INCLUDE_DIRS   - where to find yeticc.h
#   YETICC_LIBRARIES      - List of libraries when using libyeticc.
#   YETICC_FOUND          - True if libyeticc found.
#   YETICC_VERSION	  - Version of found libyeticc.

find_package(PkgConfig REQUIRED)
pkg_check_modules(YETICC libyeticc)

# handle the QUIETLY and REQUIRED arguments and set TASN_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(YETICC
                                  REQUIRED_VARS YETICC_LIBRARIES
                                  VERSION_VAR YETICC_VERSION)

