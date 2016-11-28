#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

  check_list->next = r->check_list;
  r->check_list = check_list;
}


static int compare_check(struct check* a, struct check* b) {
  int result = 0;
  result = strcmp(a->collection, b->collection);
  if(result == 0) {
    result = strverscmp(a->id, b->id);
  }

  return result;
}

static void swap(struct check_list* a, struct check_list* b) {
  struct check* temp = a->check;
  a->check = b->check;
  b->check = temp;
}

void sort_list(struct check_list* head) {
  struct check_list* start = head;
  struct check_list* traverse;
  struct check_list* min;

  while(start->next) {
    min = start;
    traverse = start->next;

    while(traverse) {
      if(compare_check(traverse->check, min->check) < 0) {
        min = traverse;
      }
      traverse = traverse->next;
    }
    swap(start, min);
    start = start->next;
  }
}

void report_print_summary(struct report *r, enum report_flags flags) {
  int checks_count = 0;
  int checks_passed = 0;

  sort_list(r->check_list);
  struct check_list *list = r->check_list;

  struct check* check;
  struct finding* findings;

  while(list != NULL) {
    check = list->check;
    checks_count++;
    findings = check->findings;
    if(check->result & CHECK_PASSED) {
      checks_passed++;
      if((flags & REPORT_FAILED_ONLY) == 0)
        printf("[\033[32;1mPASSED\033[0m] %s-%s: %s\n", check->collection, check->id, check->summary);
    }
    else if(check->result & CHECK_SKIPPED) {
      checks_passed++;
      if((flags & REPORT_FAILED_ONLY) == 0)
        printf("[\033[33;1m SKIP \033[0m] %s-%s: %s\n", check->collection, check->id, check->summary);
    }
    else {
      printf("[\033[31;1mFAILED\033[0m] %s-%s: %s\n", check->collection, check->id, check->summary);
      while(findings != NULL) {
        printf("     \033[31m[●]\033[0m %s\n", findings->finding);
        findings = findings->next;
      }
      if(check->result & CHECK_REACHED_MAX_FINDINGS) {
        printf("     \033[31m[●]\033[0m %s\n", "... and more");
      }
    }
    list = list->next;
  }

  printf("%d of %d checks passed (%0.0f%%)\n", checks_passed, checks_count, 100.0 * checks_passed / checks_count);
}
