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

#ifdef HAVE_SYSTEMD
void check_disabled_systemd(GDBusConnection* connection, struct check* c, const char* unit) {
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
        break;
      default:
        check_add_findingf(c, "Unable to get the status of unit %s: (%d) %s", unit, gerror->code, gerror->message);
        break;
    }
    g_error_free(gerror);
  }
  else {
    g_variant_get(reply, "(&s)", &status);
    if(strcmp(status, "disabled") != 0) {
      check_add_findingf(c, "unit %s is enabled", unit);
    }
    g_variant_unref(reply);
  }
}
#endif

void check_disabled_initd(struct check* c, const char* name) {
  glob_t globres;
  char* match;
  int rc;

  asprintf(&match, RUNLEVELS "/rc%d.d/S[0-9][0-9]%s", 3, name);
  rc = glob(match, GLOB_ERR | GLOB_NOSORT, NULL, &globres);
  if(rc == 0) {
    check_add_findingf(c, "the service %s is enabled but it should be disabled", name);
  }
  else if(rc != GLOB_NOMATCH) {
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

  check_disabled_initd(chargend, "chargen-dgram");
  check_disabled_initd(chargens, "chargen-stream");
  check_disabled_initd(daytimed, "daytime-dgram");
  check_disabled_initd(daytimes, "daytime-stream");
  check_disabled_initd(echod, "echo-dgram");
  check_disabled_initd(echos, "echo-stream");
  check_disabled_initd(tcpmuxs, "tcpmux-server");
#ifdef HAVE_SYSTEMD
  check_disabled_systemd(connection, avahi, "avahi-daemon.service");
  check_disabled_systemd(connection, cups , "cups.service");
  check_disabled_systemd(connection, nfs, "nfslock.service");
  check_disabled_systemd(connection, nfs, "rpcgssd.service");
  check_disabled_systemd(connection, nfs, "rpcbind.service");
  check_disabled_systemd(connection, nfs, "rpcidmapd.service");
  check_disabled_systemd(connection, nfs, "rpcsvcgssd.service");
#else
  check_disabled_initd(avahi, "avahi-daemon");
  check_disabled_initd(cups , "cups");
  check_disabled_initd(nfs , "nfslock");
  check_disabled_initd(nfs , "rpcgssd");
  check_disabled_initd(nfs , "rpcbind");
  check_disabled_initd(nfs , "rpcidmapd");
  check_disabled_initd(nfs , "rpcsvcgssd");
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
