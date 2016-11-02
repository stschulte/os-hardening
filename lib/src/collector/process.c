#include <harden/config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <proc/readproc.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include <harden/check.h>
#include <harden/report.h>

int collector_process_evaluate(struct report* report) {
  PROCTAB* pt;
  proc_t proc = {0};

#ifdef HAVE_SELINUX
  char* context;
  struct check* unconfined = check_new("cis", "1.4.6", "Check for Unconfined Daemons", CHECK_PASSED);
#endif


  printf("running openproc\n");
  pt = openproc(PROC_FILLSTATUS);
  if(pt == NULL) {
    fprintf(stderr, "unable to read process table");
    return -1;
  }

  while(readproc(pt, &proc) != NULL) {
#ifdef HAVE_SELINUX
    if(getpidcon(proc.tid, &context) == -1) {
      fprintf(stderr, "unable to get selinux context for process %d", proc.tid);
    }
    else {
      if(strstr(context, "initrc") != NULL) {
        check_add_findingf(unconfined, "unconfined daemon process %s (pid=%d) found with context %s", proc.cmd, proc.tid, context);
      }
      freecon(context);
    }
#endif
  }

  closeproc(pt);

#ifdef HAVE_SELINUX
  report_add_check(report, unconfined);
#endif

  return 0;
}
