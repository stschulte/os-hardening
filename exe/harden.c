#include <harden/config.h>
#include <harden/version.h>
#include <harden/util.h>
#include <harden/check.h>
#include <harden/report.h>

#include <harden/collector/kernel.h>
#include <harden/collector/files.h>
#include <harden/collector/user.h>

#ifdef HAVE_KMOD
#include <harden/collector/module.h>
#endif

#include <harden/collector/selinux.h>
#include <harden/collector/mount.h>
#include <harden/collector/environ.h>

#include <errno.h>
#include <stdio.h>

int main(int argc, char** argv) {
  struct report *r = report_new("foobar");


  util_init();
  
  printf("Collection OS information ...\n");

  printf("Running collector: kernel\n");
  collector_kernel_evaluate(r);
  printf("Running collector: files\n");
  collector_files_evaluate(r);
  printf("Running collector: user\n");
  collector_user_evaluate(r);
  printf("Running collector: module\n");
#ifdef HAVE_KMOD
  collector_module_evaluate(r);
#endif
  printf("Running collector: selinux\n");
  collector_selinux_evaluate(r);
  printf("Running collector: mount\n");
  collector_mount_evaluate(r);
  printf("Running collector: environ\n");
  collector_environ_evaluate(r);

  util_clean();

  printf("\n\nSUMMARY:\n");
  report_print_summary(r);

  report_free(r);
}
