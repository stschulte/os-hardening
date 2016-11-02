#include <harden/config.h>
#include <harden/version.h>
#include <harden/util.h>
#include <harden/check.h>
#include <harden/report.h>
#include <harden/collector.h>

#include <harden/collector/kernel.h>
#include <harden/collector/files.h>
#include <harden/collector/user.h>

#ifdef HAVE_KMOD
#include <harden/collector/module.h>
#endif
#ifdef HAVE_RPM
#include <harden/collector/rpm.h>
#endif

#ifdef HAVE_SELINUX
#include <harden/collector/selinux.h>
#endif

#include <harden/collector/mount.h>
#include <harden/collector/environ.h>
#include <harden/collector/services.h>
#include <harden/collector/grub.h>
#include <harden/collector/cron.h>
#include <harden/collector/yum.h>
#include <harden/collector/process.h>

#include <errno.h>
#include <stdio.h>

int main(int argc, char** argv) {

  enum collector_flags cflags = COLLECTOR_NONE;
  enum report_flags rflags = REPORT_NONE;

  for(int i=1; i<argc; i++) {
    char* option = argv[i];
    if(strcmp(option, "--fast") == 0)
      cflags |= COLLECTOR_FAST;
    if(strcmp(option, "--failed-only") == 0)
      rflags |= REPORT_FAILED_ONLY;
  }
  struct report *r = report_new("foobar");

  printf("Initialize utility functions\n");
  util_init();

  printf("Running collector: process\n");
  collector_process_evaluate(r);
  printf("Running collector: cron\n");
  collector_cron_evaluate(r);
  printf("Running collector: kernel\n");
  collector_kernel_evaluate(r);
  printf("Running collector: files\n");
  collector_files_evaluate(r, cflags);
  printf("Running collector: user\n");
  collector_user_evaluate(r);
  printf("Running collector: grub\n");
  collector_grub_evaluate(r);
  printf("Running collector: yum\n");
  collector_yum_evaluate(r);
#ifdef HAVE_KMOD
  printf("Running collector: module\n");
  collector_module_evaluate(r);
#endif
#ifdef HAVE_SELINUX
  printf("Running collector: selinux\n");
  collector_selinux_evaluate(r);
#endif
  printf("Running collector: mount\n");
  collector_mount_evaluate(r);
  printf("Running collector: environ\n");
  collector_environ_evaluate(r);
#ifdef HAVE_RPM
  printf("Running collector: rpm\n");
  collector_rpm_evaluate(r);
#endif
  printf("Running collector: services\n");
  collector_services_evaluate(r);

  util_clean();

  printf("\n\nSUMMARY:\n");
  report_print_summary(r, rflags);

  report_free(r);
}
