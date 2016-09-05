#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/util.h>
#include <harden/collector/user.h>

#include <pwd.h>
#include <shadow.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dirent.h>

int collector_user_evaluate(struct report* report) {
  struct passwd* user;
  struct spwd* shadow;
  struct stat sb_homedir;
  struct stat sb_dotfile;
  struct stat sb_netrc;
  struct passwd* owner;

  DIR* homedir;
  struct dirent* direntry;
  char* dotfile;
  char* netrc;

  struct check* pw_max = check_new("cis", "7.1.1", "Set Password Expiration Days", CHECK_PASSED);
  struct check* pw_min = check_new("cis", "7.1.2", "Set Password Change Minimum Number of Day", CHECK_PASSED);
  struct check* pw_warn = check_new("cis", "7.1.3", "Set Password Expiring Warning Days", CHECK_PASSED);
  struct check* root_group = check_new("cis", "7.3", "Set Default Group for root Account", CHECK_PASSED);

  struct check* home_perm = check_new("cis", "9.2.7", "Check Permissions on User Home Directories", CHECK_PASSED);
  struct check* home_owner = check_new("cis", "9.2.13", "Check User Home Directory Ownership", CHECK_PASSED);

  struct check* dotfile_perm = check_new("cis", "9.2.8", "Check User Dot File Permissions", CHECK_PASSED);

  struct check* netrc_perm = check_new("cis", "9.2.9", "Check Permissions on User .netrc Files", CHECK_PASSED);

  setpwent();
  if(errno == EACCES) {
    perror("Unable to read passwd entries. Skipping these checks");
    endpwent();
    return 1;
  }

  setspent();
  if(errno == EACCES) {
    perror("Unable to read shadow entries. Skipping these checks");
    endpwent();
    endspent();
    return 1;
  }

  while((user = getpwent()) != NULL) {
    if(user->pw_uid == 0) {
      if(user->pw_gid != 0) {
        check_add_findingf(root_group, "root user has gid %d instead of 0", user->pw_gid);
      }
      continue;
    }

    if(!is_dialog_user(user))
      continue;

    shadow = getspnam(user->pw_name);

    if(shadow->sp_max == -1) {
      check_add_findingf(pw_max, "user %s has maximum password disabled instead of 90 or less", user->pw_name);
    }
    else if(shadow->sp_max > 90) {
      check_add_findingf(pw_max, "user %s has maximum password set to %ld instead of 90 or less", user->pw_name, shadow->sp_max);
    }

    if(shadow->sp_min == -1) {
      check_add_findingf(pw_min, "user %s has minimum password disabled instead of 7 or more", user->pw_name);
    }
    else if(shadow->sp_min < 7) {
      check_add_findingf(pw_min, "user %s has minimum password set to %ld instead of 7 or more", user->pw_name, shadow->sp_max);
    }

    if(shadow->sp_warn == -1) {
      check_add_findingf(pw_warn, "user %s has password warning days disabled instead of 7 or more", user->pw_name);
    }
    else if(shadow->sp_warn < 7) {
      check_add_findingf(pw_warn, "user %s has password warning days set to %ld instead of 7 or more", user->pw_name, shadow->sp_warn);
    }

    errno = 0;
    if(stat(user->pw_dir, &sb_homedir) == 0) {
      if(S_ISDIR(sb_homedir.st_mode)) {

        /* check homedir itself */
        if((sb_homedir.st_mode & 0020) != 0) {
          check_add_findingf(home_perm, "user %s with group write permissions set on %s (%3o)", user->pw_name, user->pw_dir, sb_homedir.st_mode & 07777);
        }
        if((sb_homedir.st_mode & 0001) != 0) {
          check_add_findingf(home_perm, "user %s with other read permissions set on %s (%3o)", user->pw_name, user->pw_dir, sb_homedir.st_mode & 07777);
        }
        if((sb_homedir.st_mode & 0002) != 0) {
          check_add_findingf(home_perm, "user %s with other write permissions set on %s (%3o)", user->pw_name, user->pw_dir, sb_homedir.st_mode & 07777);
        }
        if((sb_homedir.st_mode & 0004) != 0) {
          check_add_findingf(home_perm, "user %s with other execute permissions set on %s (%3o)", user->pw_name, user->pw_dir, sb_homedir.st_mode & 07777);
        }

        if(user->pw_uid >= 500 && strcmp(user->pw_name, "nfsnobody") != 0) {
          if(sb_homedir.st_uid != user->pw_uid) {
            if((owner = getpwuid(sb_homedir.st_uid)) != NULL) {
              check_add_findingf(home_owner, "user %s homedirectory %s is owned by %s", user->pw_name, user->pw_dir, owner->pw_name);
            }
            else {
              check_add_findingf(home_owner, "user %s homedirectory %s is owned by unknown user (uid=%u)", user->pw_name, user->pw_dir, sb_homedir.st_uid);
            }
          }
        }

        /* check all dotfiles within the homedirectory */
        homedir = opendir(user->pw_dir);
        while((direntry = readdir(homedir)) != NULL) {
          if((strcmp(direntry->d_name, "..") == 0) || (strcmp(direntry->d_name, ".") == 0))
            continue;

          if(strncmp(direntry->d_name, ".", 1) == 0) {
            if(strcmp(user->pw_dir, "/") == 0) {
              dotfile = malloc(strlen(direntry->d_name) + 2);
              sprintf(dotfile, "/%s", direntry->d_name);
            }
            else {
              dotfile = malloc(strlen(user->pw_dir) + strlen(direntry->d_name) + 2);
              sprintf(dotfile, "%s/%s", user->pw_dir, direntry->d_name);
            }

            stat(dotfile, &sb_dotfile);
            if((sb_dotfile.st_mode & 0020) != 0) {
              check_add_findingf(dotfile_perm, "group write permission set on following dotfile: %s (%3o)", dotfile, sb_dotfile.st_mode & 0777);
            }
            if((sb_dotfile.st_mode & 0002) != 0) {
              check_add_findingf(dotfile_perm, "other write permission set on following dotfile: %s (%3o)", dotfile, sb_dotfile.st_mode & 0777);
            }
            free(dotfile);
          }
        }
        closedir(homedir);

        /* check .netrc file */
        if(strcmp(user->pw_dir, "/") == 0) {
          netrc = strdup("/.netrc");
        }
        else {
          netrc = malloc(strlen(user->pw_dir) + 1 + strlen(".netrc") + 1);
          sprintf(netrc, "%s/%s", user->pw_dir, ".netrc");
        }
        if(stat(netrc, &sb_netrc) == 0) {;
          if(sb_netrc.st_mode & 0040)
            check_add_findingf(netrc_perm, "group read set on %s (mode=%3o)", netrc, sb_netrc.st_mode & 0777);
          if(sb_netrc.st_mode & 0020)
            check_add_findingf(netrc_perm, "group write set on %s (mode=%3o)", netrc, sb_netrc.st_mode & 0777);
          if(sb_netrc.st_mode & 0010)
            check_add_findingf(netrc_perm, "group execute set on %s (mode=%3o)", netrc, sb_netrc.st_mode & 0777);
          if(sb_netrc.st_mode & 0004)
            check_add_findingf(netrc_perm, "other read set on %s (mode=%3o)", netrc, sb_netrc.st_mode & 0777);
          if(sb_netrc.st_mode & 0002)
            check_add_findingf(netrc_perm, "other write set on %s (mode=%3o)", netrc, sb_netrc.st_mode & 0777);
          if(sb_netrc.st_mode & 0001)
            check_add_findingf(netrc_perm, "other execute set on %s (mode=%3o)", netrc, sb_netrc.st_mode & 0777);
        }
        free(netrc);
      }
    }
  }
  endpwent();
  endspent();


  report_add_check(report, pw_max);
  report_add_check(report, pw_min);
  report_add_check(report, pw_warn);
  report_add_check(report, root_group);
  report_add_check(report, home_perm);
  report_add_check(report, home_owner);
  report_add_check(report, dotfile_perm);
  report_add_check(report, netrc_perm);
  return 0;
}
