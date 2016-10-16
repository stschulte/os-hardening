#ifndef _REPORT_H
#define _REPORT_H

#include <harden/check.h>

enum report_flags {
  REPORT_NONE = 0,
  REPORT_FAILED_ONLY = 1,
};

struct report {
  char* caption;
  struct check_list* check_list;
};

void report_add_check(struct report* r, struct check* c);
void report_print_summary(struct report* r, enum report_flags flags);
struct report* report_new(const char* caption);
void report_free(struct report* report);

#endif
