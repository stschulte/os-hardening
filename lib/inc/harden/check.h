#ifndef _CHECK_H
#define _CHECK_H

#define MAX_FINDING_LENGTH 1024
#define CHECK_MAX_FINDINGS 200

#include <string.h>

enum check_result {
  CHECK_UNKNOWN              = 0,
  CHECK_PASSED               = 1,
  CHECK_FAILED               = 2,
  CHECK_SKIPPED              = 4,
  CHECK_REACHED_MAX_FINDINGS = 8
};

struct finding {
  char finding[MAX_FINDING_LENGTH];
  struct finding* next;
};

struct check_list {
  struct check* check;
  struct check_list* next;
};

void check_list_free(struct check_list* check_list);

struct check {
  char* collection;
  char* id;
  char* summary;
  enum check_result result;
  struct finding* findings;
  int num_findings;
};


struct check* check_new(const char* collection, const char* id, const char* summary, enum check_result result);

void check_add_finding(struct check* check, const char* description);
void check_add_findingf(struct check* check, const char* fmt, ...) __attribute__((format (printf, 2, 3)));

void check_free(struct check* check);

#endif
