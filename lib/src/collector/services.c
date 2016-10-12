#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <harden/config.h>
#include <harden/check.h>
#include <harden/report.h>
#include <harden/collector/services.h>

#ifdef HAVE_SYSTEMD
#include <gio/gio.h>
#endif


#ifdef HAVE_SYSTEMD
void check_disabled_systemd(GDBusConnection* connection, struct check* c, const char* unit) {
  GError *gerror = NULL;
  const char* status = NULL;

  GVariant* reply = g_dbus_connection_call_sync(connection,
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    "GetUnitFileState",
    g_variant_new("(s)", unit),
    NULL,
    G_DBUS_CALL_FLAGS_NONE,
    100,
    NULL,
    &gerror);

  if(reply == NULL) {
    /* we most likely got no reply */
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

  struct check* avahi = check_new("cis", "3.3", "Disable Avahi Server", CHECK_PASSED);
  struct check* cups  = check_new("cis", "3.4", "Disable Print Server - CUPS", CHECK_PASSED);
  struct check* nfs   = check_new("cis", "3.8", "Disable NFS and RPC", CHECK_PASSED);

#ifdef HAVE_SYSTEMD
  check_disabled_systemd(connection, avahi, "avahi-daemon.service");
  check_disabled_systemd(connection, cups , "cups.service");
  check_disabled_systemd(connection, nfs, "nfslock.service");
  check_disabled_systemd(connection, nfs, "rpcgssd.service");
  check_disabled_systemd(connection, nfs, "rpcbind.service");
  check_disabled_systemd(connection, nfs, "rpcidmapd.service");
  check_disabled_systemd(connection, nfs, "rpcsvcgssd.service");
#endif

  report_add_check(report, avahi);
  report_add_check(report, cups);
  report_add_check(report, nfs);

#ifdef HAVE_SYSTEMD
  g_object_unref(connection);
#endif

  return 0;
}
