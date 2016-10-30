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

#include <errno.h>

int collector_environ_evaluate(struct report* report) {
  struct check* rootpath = check_new("cis", "9.2.6", "Ensure root PATH Integrity", CHECK_PASSED);

  const char* s = getenv("PATH");
  char* buffer = strdup(s);
  char* path;

  struct stat sb;
  struct passwd* owner;

  path = strsep(&buffer, ":");
  while(path != NULL) {
    if(strcmp(path, "") == 0) {
      check_add_findingf(rootpath, "PATH contains an empty directory (PATH=%s)", s);
    }
    if(strcmp(path, ".") == 0) {
      check_add_findingf(rootpath, "PATH contains \".\" (PATH=%s)", s);
    }

    if(stat(path, &sb) == 0) {
      if(S_ISDIR(sb.st_mode)) {
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
      }
      else {
        check_add_findingf(rootpath, "%s is not a directory", path);
      }
    }
    else {
      switch(errno) {
      case ENOTDIR:
        check_add_findingf(rootpath, "some component of %s is not a directory", path);
        break;
      case ENOENT:
        check_add_findingf(rootpath, "%s does not exist", path);
        break;
      default:
        check_add_findingf(rootpath, "unable to stat %s: %s", path, strerror(errno));
        break;
      }
    }

    path = strsep(&buffer, ":");
  }
  
  free(buffer);
  report_add_check(report, rootpath);
  return 0;
}
