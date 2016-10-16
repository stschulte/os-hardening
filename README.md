# os-hardening

Check the hardening status of your linux server according to [CIS](https://benchmarks.cisecurity.org/downloads/benchmarks/)

The Center for Internet Security has published some best practices on how to
configure your server. This project has the aim to help you check if these are
implemented.

It will no remediate these issues but it will provide some helpful messages.

## Build

To build the project you have to have `cmake` installed. You further need the
appropiate devel packages for
- `rpm` (mandatory)
- `libselinux` (optional, but checks for selinux will be absent without it)
- `libsystemd` and `gio-2.0` (optional) for systemd checks

to build the program run

    mkdir build
    cmake ..
    make

## Goals

- don't waste my time: If we can verify multiple checks at once - e.g. "every
  file should have a known user" and "every file should have a known group",
  do not go over the filesystem twice
- provide helpful messages. Tell us *why* a check failed.
- don't depend on state. Don't cache results

## Why C

I started the project initially to learn C. So writing in python, perl, ruby, ...
certainly would not have helped me here.

Secondly almost everything can be checked with relativly easy to use C APIs and
we do not have to query the output of some external program (in fact we do not
run *any* other program right now). E.g. instead of parsing the output of `rpm`
to check wether or not a program is installed, we just use the `rpm` library
directly to iterate over packages.
