#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/kernel.h>

static const char PROC_PATH[] = "/proc/sys/";

static void verify_kernel_value(struct check* check, const char* key, const char* expected_value) {
  FILE* fp;
  char filename[PATH_MAX];
  char kernelvalue[1024];

  snprintf(filename, PATH_MAX, "%s%s", PROC_PATH, key);

  char* p = strchr(filename, '.');
  while(p) {
    *p = '/';
    p = strchr(p+1, '.');
  }

  fp = fopen(filename, "r");
  if(!fp) {
    switch(errno) {
    case ENOENT:
      check_add_findingf(check, "The kernel parameter %s could not be found", key);
      break;
    case EACCES:
      check_add_findingf(check, "The kernel parameter %s cannot be read", key);
      break;
    }
  }
  else {
    errno = 0;
    if(fgets(kernelvalue, sizeof kernelvalue, fp)) {
      kernelvalue[strcspn(kernelvalue,"\n")] = '\0';
      if(strcmp(kernelvalue, expected_value) != 0) {
        check_add_findingf(check, "Kernelparameter %s is set to %s instead of %s", key, kernelvalue, expected_value);
      }
    }
  }
}

int collector_kernel_evaluate(struct report* report) {
  struct check* redirect = check_new("cis", "4.1.2", "Disable Send Packet Redirects", CHECK_PASSED);
  struct check* source_route = check_new("cis", "4.2.1", "Disable Source Routed Packet Acceptance", CHECK_PASSED);
  struct check* icmpredirect = check_new("cis", "4.2.2", "Disable ICMP Redirect Acceptance", CHECK_PASSED);
  struct check* secureredirect = check_new("cis", "4.2.3", "Disable Secure ICMP Redirect Acceptance", CHECK_PASSED);
  struct check* log = check_new("cis", "4.2.4", "Log Suspicious Packets", CHECK_PASSED);
  struct check* broadcast = check_new("cis", "4.2.5", "Enable Ignore Broadcast Requests", CHECK_PASSED);
  struct check* baderror = check_new("cis", "4.2.6", "Enable Bad Error Message Protection", CHECK_PASSED);
  struct check* route = check_new("cis", "4.2.7", "Enable RFC-recommended Source Route Validation", CHECK_PASSED);
  struct check* syncookies = check_new("cis", "4.2.8", "Enable TCP SYN Cookies", CHECK_PASSED);

  verify_kernel_value(redirect, "net.ipv4.conf.all.send_redirects", "0");
  verify_kernel_value(redirect, "net.ipv4.conf.default.send_redirects", "0");
  report_add_check(report, redirect);

  verify_kernel_value(source_route, "net.ipv4.conf.all.accept_source_route", "0");
  verify_kernel_value(source_route, "net.ipv4.conf.default.accept_source_route", "0");
  report_add_check(report, source_route);

  verify_kernel_value(icmpredirect, "net.ipv4.conf.all.accept_redirects", "0");
  verify_kernel_value(icmpredirect, "net.ipv4.conf.default.accept_redirects", "0");
  report_add_check(report, icmpredirect);

  verify_kernel_value(secureredirect, "net.ipv4.conf.all.secure_redirects", "0");
  verify_kernel_value(secureredirect, "net.ipv4.conf.default.secure_redirects", "0");
  report_add_check(report, secureredirect);

  verify_kernel_value(log, "net.ipv4.conf.all.log_martians", "1");
  verify_kernel_value(log, "net.ipv4.conf.default.log_martians", "1");
  report_add_check(report, log);

  verify_kernel_value(broadcast, "net.ipv4.icmp_echo_ignore_broadcasts", "1");
  report_add_check(report, broadcast);

  verify_kernel_value(baderror, "net.ipv4.icmp_ignore_bogus_error_responses", "1");
  report_add_check(report, baderror);

  verify_kernel_value(route, "net.ipv4.conf.all.rp_filter", "1");
  verify_kernel_value(route, "net.ipv4.conf.default.rp_filter", "1");
  report_add_check(report, route);

  verify_kernel_value(syncookies, "net.ipv4.tcp_syncookies", "1");
  report_add_check(report, syncookies);

  return 0;
}
