#include <stdlib.h>
#include <harden/check.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

struct check* check_new(const char* collection, const char* id, const char* summary, enum check_result result) {
  struct check* check = malloc(sizeof(struct check));

  check->collection = strdup(collection);
  check->id = strdup(id);
  check->summary = strdup(summary);
  check->result = result;
  check->findings = NULL;
  check->findings_last = NULL;
  return check;
}

void check_add_finding(struct check* check, const char* description) {
  struct finding *finding = malloc(sizeof(struct finding));

  strncpy(finding->finding, description, MAX_FINDING_LENGTH);
  finding->next = NULL;

  if(check->findings == NULL) {
    check->findings = finding;
    check->findings_last = finding;
  }
  else {
    check->findings_last->next = finding;
    check->findings_last = finding;
  }

  check->result = CHECK_FAILED;
}

void check_add_findingf(struct check* check, const char* fmt, ...) {
  char finding[MAX_FINDING_LENGTH];
  va_list arg;

  va_start(arg, fmt);
  vsnprintf(finding, MAX_FINDING_LENGTH, fmt, arg);
  va_end(arg);

  check_add_finding(check, finding);
}

void check_list_free(struct check_list* check_list) {
  struct check_list* current = check_list;
  struct check_list* next;

  while(current != NULL) {
    next = current->next;
    check_free(current->check);
    free(current);
    current = next;
  }
}

bool check_passed(struct check* check) {
  return (check->result == CHECK_PASSED);
}

bool check_failed(struct check* check) {
  return (check->result != CHECK_PASSED);
}

void check_free(struct check* check) {
  struct finding *current_finding;
  struct finding *next_finding;

  if(check == NULL)
    return;

  current_finding = check->findings;
  while(current_finding != NULL) {
    next_finding = current_finding->next;
    //printf("Free finding with string %s\n", current_finding->finding);
    free(current_finding);
    current_finding = next_finding;
  }

  //printf("Free check %s-%s\n", check->collection, check->id);
  free(check->summary);
  free(check->id);
  free(check->collection);
  free(check);
}