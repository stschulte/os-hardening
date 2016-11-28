#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <regex.h>

#include <errno.h>
#include <dirent.h>
#include <limits.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/cron.h>

#define SYSCRONTAB    "/etc/crontab"
#define SYS_CROND_DIR "/etc/cron.d"
#define SPOOL_DIR     "/var/spool/cron"

#define REGEX_CRONTAB_TIME_ANY "^[0-9/*]+[[:blank:]]+[0-9/*]+[[:blank:]]+[0-9/*]+[[:blank:]]+[0-9/*]+[[:blank:]]+[0-9/*]+[[:blank:]]+"

#define REGEX_CRONTAB_AIDE_COMMAND "(/usr/sbin/aide|/sbin/aide|/usr/bin/aide.wrapper) .*--check.*$"

#define REGEX_AIDE_CRONTAB  REGEX_CRONTAB_TIME_ANY                    REGEX_CRONTAB_AIDE_COMMAND
#define REGEX_AIDE_CRONTABD REGEX_CRONTAB_TIME_ANY "root[[:blank:]]+" REGEX_CRONTAB_AIDE_COMMAND

int not_a_crontab(struct dirent* entry) {
  size_t len = strlen(entry->d_name);

  if(entry->d_name[0] == '.')
    return 1;

  if(entry->d_name[0] == '#')
    return 1;

  if((len > 0) && (entry->d_name[len-1] == '~'))
    return 1;

  if((len > 8) && (strncmp(entry->d_name + len - 8, ".rpmsave", 8) == 0))
    return 1;
  if((len > 8) && (strncmp(entry->d_name + len - 8, ".rpmorig", 8) == 0))
    return 1;
  if((len > 7) && (strncmp(entry->d_name + len - 7, ".rpmnew", 7) == 0))
    return 1;

  return 0;
}

int process_crontab(const char* tabname, regex_t* regex) {
  FILE* fd;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  int found = 0;

  fd = fopen(tabname, "r");
  if(fd == NULL) {
    fprintf(stderr, "unable to open crontab %s: %s", tabname, strerror(errno));
    return -1;
  }

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

int collector_cron_evaluate(struct report* report) {
  DIR* dir;
  struct dirent* dirent;

  char crontab[PATH_MAX];

  struct check* aide = check_new("cis", "1.3.2", "Implement Periodic Execution of File Integrity", CHECK_PASSED);

  /* compile the regex once so we can reuse them in every cron file */
  regex_t reg_aide_cron;
  regex_t reg_aide_crond;
  
  regcomp(&reg_aide_cron,  REGEX_AIDE_CRONTAB,  REG_EXTENDED | REG_NOSUB);
  regcomp(&reg_aide_crond, REGEX_AIDE_CRONTABD, REG_EXTENDED | REG_NOSUB);

  /* assume the cronjob is not present until we can find it */
  aide->result = CHECK_FAILED;

  /* check the system crontab (/etc/crontab) */
  if(process_crontab(SYSCRONTAB, &reg_aide_cron) == 1)
    aide->result = CHECK_PASSED;

  /* check every crontab in /etc/cron.d */
  if((dir = opendir(SYS_CROND_DIR)) == NULL) {
    fprintf(stderr, "unable to open cron directory %s: %s\n", SYS_CROND_DIR, strerror(errno));
  }
  else {
    while((dirent = readdir(dir)) != NULL) {
      if(not_a_crontab(dirent))
        continue;

      snprintf(crontab, PATH_MAX, "%s/%s", SYS_CROND_DIR, dirent->d_name);
      if(process_crontab(crontab, &reg_aide_crond) == 1)
        aide->result = CHECK_PASSED;
    }
    closedir(dir);
  }

  /* check every user crontab in /var/spool/cron */
  if((dir = opendir(SPOOL_DIR)) == NULL) {
    fprintf(stderr, "unable to open cron directory %s: %s\n", SPOOL_DIR, strerror(errno));
  }
  else {
    while((dirent = readdir(dir)) != NULL) {
      if(not_a_crontab(dirent))
        continue;

      /* we only care about root's crontab */
      if(strcmp(dirent->d_name, "root") != 0)
        continue;

      snprintf(crontab, PATH_MAX, "%s/%s", SPOOL_DIR, dirent->d_name);
      if(process_crontab(crontab, &reg_aide_cron) == 1)
        aide->result = CHECK_PASSED;
    }
    closedir(dir);
  }

  regfree(&reg_aide_cron);
  regfree(&reg_aide_crond);

  if(aide->result == CHECK_FAILED)
    check_add_findingf(aide, "no aide --check cronjob found in any of root's crontabs");
  
  report_add_check(report, aide);
  return 0;
}
