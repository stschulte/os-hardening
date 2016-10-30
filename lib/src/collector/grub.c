#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <harden/util.h>
#include <harden/collector.h>
#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/grub.h>

#include <errno.h>

#define GRUB_CONF "/etc/grub.conf"

int collector_grub_evaluate(struct report* report) {
  FILE* stream;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;

  struct check* grubselinux = check_new("cis", "1.4.1", "Enable SELinux in /etc/grub.conf", CHECK_PASSED);
  struct check* grubpw = check_new("cis", "1.5.3", "Set Boot Loader Password", CHECK_PASSED);

  report_add_new_check_perm(report, "cis", "1.5.1", "Set User/Group Owner on /etc/grub.conf", "/etc/grub.conf", "root", "root", 0, CHECK_EXIST | CHECK_OWNER | CHECK_GROUP);
  report_add_new_check_perm(report, "cis", "1.5.2", "Set Permissions on /etc/grub.conf", "/etc/grub.conf", "root", "root", 0600, CHECK_EXIST | CHECK_MODE);


  if((stream = fopen(GRUB_CONF, "r")) == NULL) {
    check_add_findingf(grubpw, "unable to open %s: %s", GRUB_CONF, strerror(errno));
  }
  else {
    /* assume no password is present in grub.conf until we can prove otherwise */
    grubpw->result = CHECK_FAILED;
    while((read = getline(&line, &len, stream)) != -1) {
      if(strncmp(line, "password", 8) == 0) {
        grubpw->result = CHECK_PASSED;
      }
      if(strstr(line, "selinux=0") != NULL) {
        check_add_findingf(grubselinux, "selinux=0 found in %s", GRUB_CONF);
      }
      if(strstr(line, "enforcing=0") != NULL) {
        check_add_findingf(grubselinux, "enforcing=0 found in %s", GRUB_CONF);
      }
    }
    free(line);
    fclose(stream);

    if(grubpw->result == CHECK_FAILED) {
      check_add_findingf(grubpw, "no password set in /etc/grub.conf");
    }
  }

  report_add_check(report, grubpw);
  report_add_check(report, grubselinux);
  return 0;
}
