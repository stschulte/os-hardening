#ifndef HARDEN_COLLECTOR_MODULE_H
#define HARDEN_COLLECTOR_MODULE_H

#include <libkmod.h>
#include <harden/report.h>
#include <harden/check.h>

static void check_module(struct check* check, const char* modname, struct kmod_ctx* ctx);
int collector_module_evaluate(struct report* report);

#endif
