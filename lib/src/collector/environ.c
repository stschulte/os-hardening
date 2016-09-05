#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <pwd.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/environ.h>

int collector_environ_evaluate(struct report* report) {
  struct check* rootpath = check_new("cis", "9.2.6", "Ensure root PATH Integrity", CHECK_PASSED);

  const char* s = getenv("PATH");
  char* buffer = strdup(s);
  char* path;

  struct stat sb;
  struct passwd* owner;

  path = strtok(buffer, ":");
  while(path != NULL) {
    if(strcmp(path, "") == 0) {
      check_add_findingf(rootpath, "PATH contains an empty directory (PATH=%s)", s);
    }
    if(strcmp(path, ".") == 0) {
      check_add_findingf(rootpath, "PATH contains \".\" (PATH=%s)", s);
    }
    stat(path, &sb);
    if((sb.st_mode & 00020) != 0) {
      check_add_findingf(rootpath, "Group write permission set on %s (%03o) (PATH=%s)", path, sb.st_mode & 07777, s);
    }
    if((sb.st_mode & 00002) != 0) {
      check_add_findingf(rootpath, "Other write permission set on %s (%03o) (PATH=%s)", path, sb.st_mode & 07777, s);
    }
    if(sb.st_uid != 0) {
      owner = getpwuid(sb.st_uid);
      if(owner == NULL)
        check_add_findingf(rootpath, "Directory %s is owned by an unknown user instead of root (PATH=%s)", path, s);
      else
        check_add_findingf(rootpath, "Directory %s is owned by %s instead of root (PATH=%s)", path, owner->pw_name, s);
    }

    path = strtok(NULL, ":");
  }
  
  free(buffer);
  report_add_check(report, rootpath);
  return 0;
}
