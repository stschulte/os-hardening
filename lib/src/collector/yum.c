#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <dirent.h>
#include <limits.h>

#include <sys/types.h>
#include <regex.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/cron.h>

#define YUMREPODIR "/etc/yum/yum.repos.d"

static int not_a_repo(struct dirent* entry) {
  size_t len = strlen(entry->d_name);

  if(entry->d_name[0] == '.')
    return 1;

  if(entry->d_name[0] == '#')
    return 1;

  if((len > 5) && (strncmp(entry->d_name + len - 5, ".repo", 5) != 0))
    return 1;

  return 0;
}

static int check_file(const char* file, regex_t* regex) {
  FILE* fd;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  int found = 0;

  fd = fopen(file, "r");
  if(fd == NULL)
    return -1;

  while((read = getline(&line, &len, fd)) != -1) {
    if(regexec(regex, line, 0, NULL, 0) == 0) {
      found = 1;
      break;
    }
  }
  
  free(line);
  fclose(fd);

  return found;
}

int collector_yum_evaluate(struct report* report) {
  DIR* dir;
  struct dirent* dirent;

  char repofile[PATH_MAX];

  regex_t gpg_disabled;

  struct check* gpg = check_new("cis", "1.2.3", "Verify that gpgcheck is Globally Activated", CHECK_PASSED);

  regcomp(&gpg_disabled, "^[[:blank:]]*gpgcheck[[:blank:]]*=[[:blank:]]*0", REG_EXTENDED | REG_NOSUB);

  if(check_file("/etc/yum.conf", &gpg_disabled) == 1)
    check_add_findingf(gpg, "gpgcheck is disabled in file %s", "/etc/yum.conf");

  if(check_file("/etc/yum/yum.conf", &gpg_disabled) == 1)
    check_add_findingf(gpg, "gpgcheck is disabled in file %s", "/etc/yum/yum.conf");

  /* check every file in /etc/yum.repos.d */
  if((dir = opendir(YUMREPODIR)) == NULL) {
    fprintf(stderr, "unable to open yum directory %s: %s\n", YUMREPODIR,  strerror(errno));
  }
  else {
    while((dirent = readdir(dir)) != NULL) {
      if(not_a_repo(dirent))
        continue;

      snprintf(repofile, PATH_MAX, "%s/%s", YUMREPODIR, dirent->d_name);
      if(check_file(repofile, &gpg_disabled) == 1)
        check_add_findingf(gpg, "gpgcheck is disabled in file %s", repofile);
    }
    closedir(dir);
  }

  regfree(&gpg_disabled);

  report_add_check(report, gpg);
  return 0;
}
