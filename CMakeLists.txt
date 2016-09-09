cmake_minimum_required (VERSION 2.8.11)
project (harden C)

set (PROGRAM_NAME  "oscheck")
set (HARDEN_VERSION_MAJOR 0)
set (HARDEN_VERSION_MINOR 1)
set (HARDEN_VERSION_PATCH 0)

set (HARDEN_PASSWORD_MIN_AGE 7)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra")

set(HARDEN_SOURCES exe/harden.c)

find_package(PkgConfig)
pkg_check_modules(KMOD libkmod)
pkg_check_modules(SELINUX REQUIRED libselinux)

LIST(APPEND HARDEN_SOURCES lib/src/check.c)
LIST(APPEND HARDEN_SOURCES lib/src/report.c)
LIST(APPEND HARDEN_SOURCES lib/src/util.c)
LIST(APPEND HARDEN_SOURCES lib/src/collector/kernel.c)
LIST(APPEND HARDEN_SOURCES lib/src/collector/files.c)
LIST(APPEND HARDEN_SOURCES lib/src/collector/user.c)
LIST(APPEND HARDEN_SOURCES lib/src/collector/selinux.c)
LIST(APPEND HARDEN_SOURCES lib/src/collector/mount.c)
LIST(APPEND HARDEN_SOURCES lib/src/collector/environ.c)

if(KMOD_FOUND)
  set(HAVE_KMOD 1)
  LIST(APPEND HARDEN_SOURCES lib/src/collector/module.c)
endif()

configure_file( "${PROJECT_SOURCE_DIR}/lib/config.h.in"     "${PROJECT_SOURCE_DIR}/lib/inc/harden/config.h")
configure_file( "${PROJECT_SOURCE_DIR}/lib/version.h.in"    "${PROJECT_SOURCE_DIR}/lib/inc/harden/version.h")
configure_file( "${PROJECT_SOURCE_DIR}/lib/parameters.h.in" "${PROJECT_SOURCE_DIR}/lib/inc/harden/parameters.h")

include_directories( "${PROJECT_SOURCE_DIR}/lib/src"
  "${PROJECT_SOURCE_DIR}/lib/inc")

add_executable(harden ${HARDEN_SOURCES})
target_link_libraries( harden ${SELINUX_LIBRARIES})

if(KMOD_FOUND)
  target_link_libraries( harden ${KMOD_LIBRARIES} )
endif()
