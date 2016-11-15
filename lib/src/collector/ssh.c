#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <harden/util.h>
#include <harden/collector.h>
#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/ssh.h>

#include <errno.h>

#define SSHD_CONF "/etc/ssh/sshd_config"

#define LINE_COMMENT       0
#define LINE_INCOMPLETE    1
#define LINE_CONFIG        2
#define LINE_MATCH         3

static int parse_line(char* line, char** key, char** value) {
  char* ptr;

  /* ignore leading whitespace */
  ptr = line + strspn(line, " \r\t\n");

  if(*ptr == '\0' || *ptr == '#') {
    *key = NULL;
    *value = NULL;
    return LINE_COMMENT;
  }

  /* read to the next whitespace or equal sign (=end of key) */
  *key = ptr;
  ptr = strpbrk(ptr, " \r\t\n=");
  if(ptr == NULL) {
    *value = NULL;
    return LINE_INCOMPLETE;
  }

  /* terminate the key */
  *ptr = '\0';

  /* skip over whitespaces until we get to the value */
  ptr += strspn(ptr + 1, " \r\t\n=") + 1;

  /* remove a trailing newline from the config */
  ptr[strcspn(ptr," \r\t\n")] = '\0';

  *value = ptr;

  if(strcasecmp(*key, "match") == 0)
    return LINE_MATCH;
  else
    return LINE_CONFIG;

}

int collector_ssh_evaluate(struct report* report) {

  struct check* proto = check_new("cis", "6.2.1", "Set SSH Protocol to 2", CHECK_PASSED);
  struct check* loglevel = check_new("cis", "6.2.2", "Set LogLevel to INFO", CHECK_PASSED);
  struct check* x11forward = check_new("cis", "6.2.4", "Disable SSH X11 Forwarding", CHECK_PASSED);
  struct check* authtries = check_new("cis", "6.2.5", "Set SSH MaxAuthTries to 4 or Less", CHECK_PASSED);
  struct check* ignorerhosts = check_new("cis", "6.2.6", "Set SSH IgnoreRhosts to Yes", CHECK_PASSED);
  struct check* ignorehosts = check_new("cis", "6.2.7", "Set SSH HostbasedAuthentication to No", CHECK_PASSED);
  struct check* rootlogin = check_new("cis", "6.2.8", "Disable SSH Root Login", CHECK_PASSED);
  struct check* permitempty = check_new("cis", "6.2.9", "Set SSH PermitEmptyPasswords to No", CHECK_PASSED);
  struct check* userenv = check_new("cis", "6.2.10", "Do Not Allow Users to Set Environment Options", CHECK_PASSED);

  FILE* stream;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;

  char* key;
  char* value;
  int linetype;

  /* some settings will default to non-compliant values so
   * we have to track if we have not found them in sshd_config */
  int found_x11forward = 0;
  int found_authtries = 0;
  int found_rootlogin = 0;

  if((stream = fopen(SSHD_CONF, "r")) == NULL) {
  }
  else {
    for(int linenr = 1; (read = getline(&line, &len, stream)) != -1; linenr++) {
      linetype = parse_line(line, &key, &value);
      if(linetype == LINE_COMMENT) {
        continue;
      }
      else if(linetype == LINE_MATCH) {
        break;
      }

      /* parameters that will be correct by default so we only need to check if they
       * are explicitly set to different values */

      if(strcasecmp(key, "Protocol") == 0 && strcasecmp(value, "2") != 0)
        check_add_findingf(proto, "%s:%d Protocol is set to %s instead of 2", SSHD_CONF, linenr, value);

      if(strcasecmp(key, "LogLevel") == 0 && strcasecmp(value, "INFO") != 0)
        check_add_findingf(loglevel, "%s:%d LogLevel is set to %s instead of INFO", SSHD_CONF, linenr, value);

      if(strcasecmp(key, "IgnoreRhosts") == 0 && strcasecmp(value, "yes") != 0)
        check_add_findingf(ignorerhosts, "%s:%d IgnoreRhosts is set to %s instead of yes", SSHD_CONF, linenr, value);

      if(strcasecmp(key, "HostbasedAuthentication") == 0 && strcasecmp(value, "no") != 0)
        check_add_findingf(ignorehosts, "%s:%d HostbasedAuthentication is set to %s instead of no", SSHD_CONF, linenr, value);

      if(strcasecmp(key, "PermitEmptyPasswords") == 0 && strcasecmp(value, "no") != 0)
        check_add_findingf(permitempty, "%s:%d PermitEmptyPasswords is set to %s instead of no", SSHD_CONF, linenr, value);

      if(strcasecmp(key, "PermitUserEnvironment") == 0 && strcasecmp(value, "no") != 0)
        check_add_findingf(userenv, "%s:%d PermitUserEnvironment is set to %s instead of no", SSHD_CONF, linenr, value);

      if(strcasecmp(key, "X11Forwarding") == 0) {
        found_x11forward = 1;
        if(strcasecmp(value, "no") != 0) {
          check_add_findingf(x11forward, "%s:%d X11Forwarding is set to %s instead of no", SSHD_CONF, linenr, value);
        }
      }

      if(strcasecmp(key, "MaxAuthTries") == 0) {
        found_authtries = 1;
        if(atoi(value) > 4) {
          check_add_findingf(authtries, "%s:%d MaxAuthTries is set to %s instead of 4 or less", SSHD_CONF, linenr, value);
        }
      }

      if(strcasecmp(key, "PermitRootLogin") == 0) {
        found_rootlogin = 1;
        if(strcasecmp(value, "no") != 0) {
          check_add_findingf(rootlogin, "%s:%d PermitRootLogin is set to %s instead of no", SSHD_CONF, linenr, value);
        }
      }
    }
    free(line);
    fclose(stream);
  }

  if(found_x11forward == 0)
    check_add_findingf(x11forward, "%s: X11Forwarding not found but should be set to no", SSHD_CONF);
  if(found_authtries == 0)
    check_add_findingf(authtries, "%s: MaxAuthTries not found but should be set to 4 or less", SSHD_CONF);
  if(found_rootlogin == 0)
    check_add_findingf(rootlogin, "%s: PermitRootLogin is not found but should be set to no", SSHD_CONF);

  report_add_check(report, proto);
  report_add_check(report, loglevel);
  report_add_check(report, x11forward);
  report_add_check(report, authtries);
  report_add_check(report, ignorerhosts);
  report_add_check(report, ignorehosts);
  report_add_check(report, rootlogin);
  report_add_check(report, permitempty);
  report_add_check(report, userenv);

  return 0;
}
