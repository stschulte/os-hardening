#include <string.h>
#include <stdio.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/module.h>

#include <libkmod.h>

static void check_module(struct check* check, const char* modname, struct kmod_ctx* ctx) {
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

void report_add_new_check_module_disabled(struct report* r, struct kmod_ctx* ctx, const char* collection, const char* id, const char* summary, const char* module) {
  struct check* c = check_new(collection, id, summary, CHECK_PASSED);

  check_module(c, module, ctx);

  report_add_check(r, c);
}

  
int collector_module_evaluate(struct report* report) {
  struct kmod_ctx* ctx = kmod_new(NULL, NULL);

  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.18", "Disable Mounting of cramfs Filesystems", "cramfs");
  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.19", "Disable Mounting of freevxfs Filesystems", "freevxfs");
  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.20", "Disable Mounting of jffs2 Filesystems", "jffs2");
  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.21", "Disable Mounting of hfs Filesystems", "hfs");
  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.22", "Disable Mounting of hfsplus Filesystems", "hfsplus");
  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.23", "Disable Mounting of squashfs Filesystems", "squashfs");
  report_add_new_check_module_disabled(report, ctx, "cis", "1.1.24", "Disable Mounting of udf Filesystems", "udf");

  kmod_unref(ctx);
  return 0;
}
