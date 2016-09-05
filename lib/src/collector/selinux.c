#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/selinux.h>

#include <selinux/selinux.h>
#include <errno.h>

int collector_selinux_evaluate(struct report* report) {
  struct check* selinux_state = check_new("cis", "1.4.2", "Set the SELinux State", CHECK_PASSED);
  struct check* selinux_policy = check_new("cis", "1.4.3", "Set the SELinux Policy", CHECK_PASSED);

  const char* pol_name;
  char* pol_path;
  int rc;

  rc = is_selinux_enabled();
  switch(rc) {
  case 1:
    // selinux is enabled
    break;
  case 0:
    check_add_finding(selinux_state, "SELinux is not enabled on this machine");
    break;
  default:
    printf("unable to determine current selinux status: %s", strerror(errno));
    check_add_finding(selinux_state, "unknown selinux state");
    break;
  }

  rc = security_getenforce();
  switch(rc) {
  case 1:
    // mode = enforcing
    break;
  case 0:
    check_add_finding(selinux_state, "selinux enforce mode is set to permissive instead of enforcing");
    break;
  default:
    check_add_finding(selinux_state, "selinux enforce mode is unknown but should be enforcing");
    break;
  }

  if(selinux_getenforcemode(&rc) == 0) {
    switch(rc) {
    case 1:
      // mode enforcing
      break;
    case 0:
      check_add_finding(selinux_state, "selinux enforce mode is set to permissive in configuration file instead of enforcing");
      break;
    case -1:
      check_add_finding(selinux_state, "selinux enforce mode is set to disabled in configuration file instead of enforcing");
      break;
    default:
      check_add_finding(selinux_state, "selinux enforce mode is unknown in configuration file but should be enforcing");
      break;
    }
  }
  else {
    printf("unable to get the configured selinux enforcemode: %s\n", strerror(errno));
  }


  pol_path = strdup(selinux_policy_root());
  if(pol_path) {
    pol_name = basename(pol_path);
    if(strcmp(pol_name, "targeted") != 0) {
      check_add_findingf(selinux_policy, "selinux policy expected to be targeted but got %s", pol_name);
    }
    free(pol_path);
  }



  report_add_check(report, selinux_state);
  report_add_check(report, selinux_policy);
  return 0;
}
