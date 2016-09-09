cmake_minimum_required (VERSION 2.8.11)
project (harden C)
add_executable(harden
  exe/harden.c
  lib/src/check.c
  lib/src/report.c
  lib/src/util.c
  lib/src/collector/kernel.c
  lib/src/collector/files.c
  lib/src/collector/user.c
  lib/src/collector/module.c
  lib/src/collector/selinux.c
  lib/src/collector/mount.c
  lib/src/collector/environ.c
)

set (PROGRAM_NAME  "oscheck")
set (HARDEN_VERSION_MAJOR 0)
set (HARDEN_VERSION_MINOR 1)
set (HARDEN_VERSION_PATCH 0)

set (HARDEN_PASSWORD_MIN_AGE 7)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra")

find_package(PkgConfig)
pkg_check_modules(KMOD REQUIRED libkmod)
pkg_check_modules(SELINUX REQUIRED libselinux)

configure_file(
  "${PROJECT_SOURCE_DIR}/lib/version.h.in"
  "${PROJECT_SOURCE_DIR}/lib/inc/harden/version.h"
)

configure_file(
  "${PROJECT_SOURCE_DIR}/lib/parameters.h.in"
  "${PROJECT_SOURCE_DIR}/lib/inc/harden/parameters.h"
)

include_directories( "${PROJECT_SOURCE_DIR}/lib/src"
  "${PROJECT_SOURCE_DIR}/lib/inc")

target_link_libraries( harden ${KMOD_LIBRARIES} ${SELINUX_LIBRARIES})
