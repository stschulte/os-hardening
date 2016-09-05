#include <string.h>
#include <stdio.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/module.h>

#include <libkmod.h>

static void check_module(struct check* check, const char* modname, struct kmod_ctx* ctx) {
  check->result = CHECK_PASSED;
  struct kmod_module *mod;

  kmod_module_new_from_name(ctx, modname, &mod);

  int state = kmod_module_get_initstate(mod);

  switch(state) {
    case KMOD_MODULE_BUILTIN:
      check_add_findingf(check, "module %s is built in the kernel", modname);
      break;
    case KMOD_MODULE_LIVE:
      check_add_findingf(check, "module %s is currently loaded", modname);
      break;
  }

  const char* path = kmod_module_get_path(mod);
  const char* cmd = kmod_module_get_install_commands(mod);
  if(path != NULL) {
    /* we have a path so the module is present and could be loaded */
    if(cmd == NULL) {
      check_add_findingf(check, "no install command defined for %s. Expected: /bin/true", modname);
    }
    else if(strcmp(cmd, "/bin/true") != 0) {
      check_add_findingf(check, "install command defined as %s instead of /bin/true", cmd);
    }
  }

  kmod_module_unref(mod);
}

  
int collector_module_evaluate(struct report* report) {
  struct check* cramfs = check_new("cis", "1.1.18", "Disable Mounting of cramfs Filesystems", CHECK_PASSED);
  struct check* freevxfs = check_new("cis", "1.1.19", "Disable Mounting of freevxfs Filesystems", CHECK_PASSED);
  struct check* jffs2 = check_new("cis", "1.1.20", "Disable Mounting of jffs2 Filesystems", CHECK_PASSED);
  struct check* hfs = check_new("cis", "1.1.21", "Disable Mounting of hfs Filesystems", CHECK_PASSED);
  struct check* hfsplus = check_new("cis", "1.1.22", "Disable Mounting of hfsplus Filesystems", CHECK_PASSED);
  struct check* squashfs = check_new("cis", "1.1.23", "Disable Mounting of squashfs Filesystems", CHECK_PASSED);
  struct check* udf = check_new("cis", "1.1.24", "Disable Mounting of udf Filesystems", CHECK_PASSED);

  struct kmod_ctx* ctx = kmod_new(NULL, NULL);

  check_module(cramfs, "cramfs", ctx);
  check_module(freevxfs, "freevxfs", ctx);
  check_module(jffs2, "jffs2", ctx);
  check_module(hfs, "hfs", ctx);
  check_module(hfsplus, "hfsplus", ctx);
  check_module(squashfs, "squashfs", ctx);
  check_module(udf, "udf", ctx);

  kmod_unref(ctx);

  report_add_check(report, cramfs);
  report_add_check(report, freevxfs);
  report_add_check(report, jffs2);
  report_add_check(report, hfs);
  report_add_check(report, hfsplus);
  report_add_check(report, squashfs);
  report_add_check(report, udf);

  return 0;
}
