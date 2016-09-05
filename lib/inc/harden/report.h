#ifndef _REPORT_H
#define _REPORT_H

#include <harden/check.h>

struct report {
  char* caption;
  struct check_list* check_list;
  struct check_list* check_list_last;
};

void report_add_check(struct report* r, struct check* c);
void report_print_summary(struct report* r);
struct report* report_new(const char* caption);
void report_free(struct report* report);

#endif
