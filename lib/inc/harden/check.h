#ifndef _CHECK_H
#define _CHECK_H

#define MAX_FINDING_LENGTH 1024

#include <string.h>
#include <stdbool.h>

enum check_result {
  CHECK_PASSED = 0,
  CHECK_FAILED = 1,
  CHECK_SKIPPED = 2
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
};


struct check* check_new(const char* collection, const char* id, const char* summary, enum check_result result);

void check_add_finding(struct check* check, const char* description);
void check_add_findingf(struct check* check, const char* fmt, ...) __attribute__((format (printf, 2, 3)));

bool check_passed(struct check* check);
bool check_failed(struct check* check);
void check_free(struct check* check);

#endif
