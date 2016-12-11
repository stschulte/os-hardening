#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <harden/config.h>
#include <harden/check.h>
#include <harden/report.h>
#include <harden/collector/services.h>

#include <glob.h>

#define RUNLEVELS "/etc"

#ifdef HAVE_SYSTEMD
#include <gio/gio.h>
#endif

#define DESIRED_ENABLED 0
#define DESIRED_DISABLED 1

#ifdef HAVE_SYSTEMD
void check_systemd(GDBusConnection* connection, struct check* c, const char* unit, int desired_state) {
  GError *gerror = NULL;
  const char* status = NULL;

  GVariant* reply = g_dbus_connection_call_sync(connection,
    "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
    "GetUnitFileState", g_variant_new("(s)", unit),
    NULL, G_DBUS_CALL_FLAGS_NONE, 100, NULL, &gerror);

  if(reply == NULL) {
    /* when we do not get a reply it could be the service is not even installed */
    switch(gerror->code) {
      case G_DBUS_ERROR_FILE_NOT_FOUND:
        if(desired_state == DESIRED_ENABLED) {
          check_add_findingf(c, "service %s not found but should be enabled", unit);
        }
        break;
      default:
        check_add_findingf(c, "Unable to get the status of unit %s: (%d) %s", unit, gerror->code, gerror->message);
        break;
    }
    g_error_free(gerror);
  }
  else {
    g_variant_get(reply, "(&s)", &status);
    if(strcmp(status, "disabled") == 0) {
      if(desired_state == DESIRED_ENABLED) {
        check_add_findingf(c, "unit %s should be enabled, but status is %s", unit, status);
      }
    }
    else {
      if(desired_state == DESIRED_DISABLED) {
        check_add_findingf(c, "unit %s should be disabled, but status is %s", unit, status);
      }
    }
    g_variant_unref(reply);
  }
}
#endif

void check_initd(struct check* c, const char* name, int desired_state) {
  glob_t globres;
  char* match;
  int rc;

  asprintf(&match, RUNLEVELS "/rc%d.d/S[0-9][0-9]%s", 3, name);
  rc = glob(match, GLOB_ERR | GLOB_NOSORT, NULL, &globres);
  if(rc == 0) {
    if(desired_state == DESIRED_DISABLED) {
      check_add_findingf(c, "the service %s is enabled but it should be disabled", name);
    }
  }
  else if(rc == GLOB_NOMATCH) {
    if(desired_state == DESIRED_ENABLED) {
      check_add_findingf(c, "the service %s is disabled but should be enabled", name);
    }
  }
  else {
    check_add_findingf(c, "failed to determine if service %s is enabled. Failed to glob pattern %s", name, match);
  }

  globfree(&globres);
  free(match);
}


int collector_services_evaluate(struct report* report) {
#ifdef HAVE_SYSTEMD
  GDBusConnection *connection;
  GError *gerror = NULL;

  connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &gerror);
  if(connection == NULL) {
    fprintf(stderr, "Unable to connect to system bus: %s\n", gerror->message);
    g_error_free(gerror);
    return -1;
  }
#endif

  struct check* chargend = check_new("cis", "2.1.12", "Disable chargen-dgram", CHECK_PASSED);
  struct check* chargens = check_new("cis", "2.1.13", "Disable chargen-stream", CHECK_PASSED);
  struct check* daytimed = check_new("cis", "2.1.14", "Disable daytime-dgram", CHECK_PASSED);
  struct check* daytimes = check_new("cis", "2.1.15", "Disable daytime-stream", CHECK_PASSED);
  struct check* echod = check_new("cis", "2.1.16", "Disable echo-dgram", CHECK_PASSED);
  struct check* echos = check_new("cis", "2.1.17", "Disable echo-stream", CHECK_PASSED);
  struct check* tcpmuxs = check_new("cis", "2.1.18", "Disable tcpmux-server", CHECK_PASSED);
  struct check* avahi = check_new("cis", "3.3", "Disable Avahi Server", CHECK_PASSED);
  struct check* cups  = check_new("cis", "3.4", "Disable Print Server - CUPS", CHECK_PASSED);
  struct check* nfs   = check_new("cis", "3.8", "Disable NFS and RPC", CHECK_PASSED);

  check_initd(chargend, "chargen-dgram", DESIRED_DISABLED);
  check_initd(chargens, "chargen-stream", DESIRED_DISABLED);
  check_initd(daytimed, "daytime-dgram", DESIRED_DISABLED);
  check_initd(daytimes, "daytime-stream", DESIRED_DISABLED);
  check_initd(echod, "echo-dgram", DESIRED_DISABLED);
  check_initd(echos, "echo-stream", DESIRED_DISABLED);
  check_initd(tcpmuxs, "tcpmux-server", DESIRED_DISABLED);
#ifdef HAVE_SYSTEMD
  check_systemd(connection, avahi, "avahi-daemon.service", DESIRED_DISABLED);
  check_systemd(connection, cups , "cups.service", DESIRED_DISABLED);
  check_systemd(connection, nfs, "nfslock.service", DESIRED_DISABLED);
  check_systemd(connection, nfs, "rpcgssd.service", DESIRED_DISABLED);
  check_systemd(connection, nfs, "rpcbind.service", DESIRED_DISABLED);
  check_systemd(connection, nfs, "rpcidmapd.service", DESIRED_DISABLED);
  check_systemd(connection, nfs, "rpcsvcgssd.service", DESIRED_DISABLED);
#else
  check_initd(avahi, "avahi-daemon", DESIRED_DISABLED);
  check_initd(cups , "cups", DESIRED_DISABLED);
  check_initd(nfs , "nfslock", DESIRED_DISABLED);
  check_initd(nfs , "rpcgssd", DESIRED_DISABLED);
  check_initd(nfs , "rpcbind", DESIRED_DISABLED);
  check_initd(nfs , "rpcidmapd", DESIRED_DISABLED);
  check_initd(nfs , "rpcsvcgssd", DESIRED_DISABLED);
#endif

  report_add_check(report, chargend);
  report_add_check(report, chargens);
  report_add_check(report, daytimed);
  report_add_check(report, daytimes);
  report_add_check(report, echod);
  report_add_check(report, echos);
  report_add_check(report, tcpmuxs);
  report_add_check(report, avahi);
  report_add_check(report, cups);
  report_add_check(report, nfs);

#ifdef HAVE_SYSTEMD
  g_object_unref(connection);
#endif

  return 0;
}
