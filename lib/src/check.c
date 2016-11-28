#include <stdlib.h>
#include <harden/check.h>
#include <stdio.h>
#include <stdarg.h>

struct check* check_new(const char* collection, const char* id, const char* summary, enum check_result result) {
  struct check* check = malloc(sizeof(struct check));

  check->collection = strdup(collection);
  check->id = strdup(id);
  check->summary = strdup(summary);
  check->result = result;
  check->findings = NULL;
  check->num_findings = 0;
  return check;
}

void check_add_finding(struct check* check, const char* description) {
  struct finding *finding;

  if(check->num_findings == CHECK_MAX_FINDINGS) {
    check->result |= CHECK_REACHED_MAX_FINDINGS;
    return;
  }

  finding = malloc(sizeof(struct finding));
  strncpy(finding->finding, description, MAX_FINDING_LENGTH);

  finding->next = check->findings;
  check->findings = finding;

  check->result = CHECK_FAILED;
  check->num_findings++;
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
