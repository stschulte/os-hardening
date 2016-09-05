#include <harden/report.h>
#include <harden/check.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>

struct report* report_new(const char* caption) {
  struct report* report = malloc(sizeof(struct report));

  report->caption = malloc(strlen(caption) + 1);
  strcpy(report->caption, caption);

  report->check_list = NULL;
  report->check_list_last = NULL;
  return report;
}

void report_free(struct report* report) {
  if(report == NULL)
    return;

  check_list_free(report->check_list);
  free(report->caption);
  free(report);
}

void report_add_check(struct report* r, struct check* c) {
  struct check_list *check_list = malloc(sizeof(struct check_list));

  check_list->check = c;
  check_list->next = NULL;

  if(r->check_list == NULL) {
    r->check_list = check_list;
    r->check_list_last = check_list;
  }
  else {
    r->check_list_last->next = check_list;
    r->check_list_last = check_list;
  }
}

void report_print_summary(struct report *r) {
  int checks_count = 0;
  int checks_passed = 0;

  struct check_list *list = r->check_list;

  struct check* check;
  struct finding* findings;
  struct winsize w;
  ioctl(0, TIOCGWINSZ, &w);

  while(list != NULL) {
    check = list->check;
    checks_count++;
    findings = check->findings;
    if(check->result == CHECK_PASSED) {
      checks_passed++;
      printf("[\033[32;1mPASSED\033[0m] %s-%s: %s\n", check->collection, check->id, check->summary);
    }
    else {
      printf("[\033[31;1mFAILED\033[0m] %s-%s: %s\n", check->collection, check->id, check->summary);
      while(findings != NULL) {
        printf("         \033[31m⤷\033[0m %s\n", findings->finding);
        findings = findings->next;
      }
    }
    list = list->next;
  }

  printf("%d of %d checks passed (%0.0f%%)\n", checks_passed, checks_count, 100.0 * checks_passed / checks_count);
}
