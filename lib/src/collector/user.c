#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/util.h>
#include <harden/collector/user.h>

#include <pwd.h>
#include <shadow.h>
#include <grp.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dirent.h>


void check_user_duplicates(struct check* duplicate_uid, struct check* duplicate_name) {
  struct passwd** available_users_by_uid;
  struct passwd** available_users_by_name;

  int idx_first = 0;
  int idx_last = 0;
  uid_t current_uid;
  char* current_name;

  int count = get_cached_users(&available_users_by_name, &available_users_by_uid);

  current_uid = available_users_by_uid[0]->pw_uid;
  idx_first = 0;
  idx_last = 0;

  /* check duplicate uids */
  for(int i=1; i < count; i++) {
    struct passwd* user = available_users_by_uid[i];

    if(user->pw_uid == current_uid)
      idx_last = i;

    if(user->pw_uid != current_uid || (i == count-1)) {
      if((idx_last - idx_first) > 0) {
        for(int j = idx_first; j <= idx_last; j++) {
          check_add_findingf(duplicate_uid, "found %d users with uid %u: %s", idx_last - idx_first + 1, current_uid, available_users_by_uid[j]->pw_name);
        }
      }
      current_uid = user->pw_uid;
      idx_first = i;
      idx_last = i;
    }
  }

  current_name = available_users_by_name[0]->pw_name;
  idx_first = 0;
  idx_last = 0;

  /* check duplicate names */
  for(int i=1; i < count; i++) {
    struct passwd* user = available_users_by_name[i];

    if(strcmp(user->pw_name, current_name) == 0)
      idx_last = i;

    if(strcmp(user->pw_name, current_name) != 0 || (i == count-1)) {
      if((idx_last - idx_first) > 0) {
        for(int j = idx_first; j <= idx_last; j++) {
          check_add_findingf(duplicate_name, "user %s has %u uids: %u", current_name, idx_last - idx_first + 1, available_users_by_name[j]->pw_uid);
        }
      }
      current_name = user->pw_name;
      idx_first = i;
      idx_last = i;
    }
  }
}

void check_group_duplicates(struct check* duplicate_gid, struct check* duplicate_name) {
  struct group** available_groups_by_gid;
  struct group** available_groups_by_name;

  int idx_first = 0;
  int idx_last = 0;
  gid_t current_gid;
  char* current_name;

  int count = get_cached_groups(&available_groups_by_name, &available_groups_by_gid);

  current_gid = available_groups_by_gid[0]->gr_gid;
  idx_first = 0;
  idx_last = 0;

  /* check duplicate uids */
  for(int i=1; i < count; i++) {
    struct group* group = available_groups_by_gid[i];

    if(group->gr_gid == current_gid)
      idx_last = i;

    if(group->gr_gid != current_gid || (i == count-1)) {
      if((idx_last - idx_first) > 0) {
        for(int j = idx_first; j <= idx_last; j++) {
          check_add_findingf(duplicate_gid, "found %d groups with gid %u: %s", idx_last - idx_first + 1, current_gid, available_groups_by_gid[j]->gr_name);
        }
      }
      current_gid = group->gr_gid;
      idx_first = i;
      idx_last = i;
    }
  }

  current_name = available_groups_by_name[0]->gr_name;
  idx_first = 0;
  idx_last = 0;

  /* check duplicate names */
  for(int i=1; i < count; i++) {
    struct group* group = available_groups_by_name[i];

    if(strcmp(group->gr_name, current_name) == 0)
      idx_last = i;

    if(strcmp(group->gr_name, current_name) != 0 || (i == count-1)) {
      if((idx_last - idx_first) > 0) {
        for(int j = idx_first; j <= idx_last; j++) {
          check_add_findingf(duplicate_name, "group %s has %u gids: %u", current_name, idx_last - idx_first + 1, available_groups_by_name[j]->gr_gid);
        }
      }
      current_name = group->gr_name;
      idx_first = i;
      idx_last = i;
    }
  }
}

void validate_homefile(struct check* check, struct passwd* user, const char* filename, mode_t mask) {
  char* path;
  struct stat sb;

  if(strcmp(user->pw_dir, "/") == 0) {
    path = malloc(strlen(filename) + 2);
    sprintf(path, "/%s", filename);
  }
  else {
    path = malloc(strlen(user->pw_dir) + strlen(filename) + 2);
    sprintf(path, "%s/%s", user->pw_dir, filename);
  }

  if(stat(path, &sb) == 0) {;
    if(mask == 0777) {
      check_add_findingf(check, "user %s: found file %s in users homedirectory: %s", user->pw_name, filename, path);
    }
    else {
      if((mask & 0040) != 0 && (sb.st_mode & 0040) != 0) {
        check_add_findingf(check, "user %s: group read set on %s (mode=%3o)", user->pw_name, path, sb.st_mode & 0777);
      }
      if((mask & 0020) != 0 && (sb.st_mode & 0020) != 0) {
        check_add_findingf(check, "user %s: group write set on %s (mode=%3o)", user->pw_name, path, sb.st_mode & 0777);
      }
      if((mask & 0010) != 0 && (sb.st_mode & 0010) != 0) {
        check_add_findingf(check, "user %s: group execute set on %s (mode=%3o)", user->pw_name, path, sb.st_mode & 0777);
      }
      if((mask & 0004) != 0 && (sb.st_mode & 0004) != 0) {
        check_add_findingf(check, "user %s: other read set on %s (mode=%3o)", user->pw_name, path, sb.st_mode & 0777);
      }
      if((mask & 0002) != 0 && (sb.st_mode & 0002) != 0) {
        check_add_findingf(check, "user %s: other write set on %s (mode=%3o)", user->pw_name, path, sb.st_mode & 0777);
      }
      if((mask & 0001) != 0 && (sb.st_mode & 0001) != 0) {
        check_add_findingf(check, "user %s: other execute set on %s (mode=%3o)", user->pw_name, path, sb.st_mode & 0777);
      }
    }
  }

  free(path);
}

void check_legacy_entry_in_file(struct check* c, const char* filename) {
  FILE* stream;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  int linenr = 0;

  stream = fopen(filename, "r");
  if(stream == NULL) {
    check_add_findingf(c, "unable to open file %s: %s", filename, strerror(errno));
    return;
  }

  while((read = getline(&line, &len, stream)) != -1) {
    linenr++;
    if(strncmp(line, "+:", 2) == 0){
      line[strcspn(line,"\n")] = '\0';
      check_add_findingf(c, "the /etc/passwd contains a legacy entry in line %d: \"%s\"", linenr, line);
    }
  }

  free(line);
  fclose(stream);
}

int parse_default_useradd(int* inactive, int* expire) {
  FILE* stream;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  stream = fopen("/etc/default/useradd", "r");
  if(stream == NULL)
    return -1;

  while((read = getline(&line, &len, stream)) != -1) {
    if(strncmp(line, "EXPIRE=", 7) == 0) {
      if(expire != NULL)
        *expire = atoi(line+7);
    }
    else if(strncmp(line, "INACTIVE=", 9) == 0) {
      if(inactive != NULL)
        *inactive = atoi(line+9);
    }
  }

  free(line);
  fclose(stream);
  return 0;
}

int collector_user_evaluate(struct report* report) {
  struct passwd* user;
  struct spwd* shadow;
  struct stat sb_homedir;
  struct passwd* owner;


  DIR* homedir;
  struct dirent* direntry;

  struct check* pw_max = check_new("cis", "7.1.1", "Set Password Expiration Days", CHECK_PASSED);
  struct check* pw_min = check_new("cis", "7.1.2", "Set Password Change Minimum Number of Day", CHECK_PASSED);
  struct check* pw_warn = check_new("cis", "7.1.3", "Set Password Expiring Warning Days", CHECK_PASSED);
  struct check* pw_empty = check_new("cis", "9.2.1", "Ensure Password Fields are Not Empty", CHECK_PASSED);

  struct check* pw_legacy = check_new("cis", "9.2.2", "Verify No Legacy \"+\" Entries Exist in /etc/passwd File", CHECK_PASSED);
  struct check* gr_legacy = check_new("cis", "9.2.3", "Verify No Legacy \"+\" Entries Exist in /etc/shadow File", CHECK_PASSED);
  struct check* sh_legacy = check_new("cis", "9.2.4", "Verify No Legacy \"+\" Entries Exist in /etc/group File", CHECK_PASSED);

  struct check* disablesysaccount = check_new("cis", "7.2", "Disable System Accounts", CHECK_PASSED);
  struct check* root_group = check_new("cis", "7.3", "Set Default Group for root Account", CHECK_PASSED);
  struct check* root = check_new("cis", "9.2.5", "Verify No UID 0 Accounts Exist Other Than root", CHECK_PASSED);

  struct check* home_perm = check_new("cis", "9.2.7", "Check Permissions on User Home Directories", CHECK_PASSED);

  struct check* unknowngid = check_new("cis", "9.2.11", "Check Groups in /etc/passwd", CHECK_PASSED);
  struct check* home_owner = check_new("cis", "9.2.13", "Check User Home Directory Ownership", CHECK_PASSED);

  struct check* dotfile_perm = check_new("cis", "9.2.8", "Check User Dot File Permissions", CHECK_PASSED);
  struct check* netrc_perm = check_new("cis", "9.2.9", "Check Permissions on User .netrc Files", CHECK_PASSED);

  struct check* rhost_exist = check_new("cis", "9.2.10", "Check for Presence of User .rhosts Files", CHECK_PASSED);
  struct check* netrc_exist = check_new("cis", "9.2.18", "Check for Presence of User .netrc Files", CHECK_PASSED);
  struct check* forward_exist = check_new("cis", "9.2.19", "Check for Presence of User .forward Files", CHECK_PASSED);

  struct check* duplicate_uid = check_new("cis", "9.2.14", "Check for Duplicate UIDs", CHECK_PASSED);
  struct check* duplicate_pwname = check_new("cis", "9.2.16", "Check for Duplicate User Names", CHECK_PASSED);

  struct check* duplicate_gid = check_new("cis", "9.2.15", "Check for Duplicate GIDs", CHECK_PASSED);
  struct check* duplicate_grname = check_new("cis", "9.2.17", "Check for Duplicate Group Names", CHECK_PASSED);

  struct check* inactive = check_new("cis", "7.5", "Lock Inactive User Accounts", CHECK_PASSED);


  check_user_duplicates(duplicate_uid, duplicate_pwname);
  check_group_duplicates(duplicate_gid, duplicate_grname);

  int default_inactive = -1;
  if(parse_default_useradd(&default_inactive, NULL) == 0) {
    if(default_inactive < 35) {
      check_add_findingf(inactive, "the default inactive value is set to %d instead of 35 or more", default_inactive);
    }
  }
  else {
    check_add_findingf(inactive, "unable to get the inactive value from /etc/default/useradd");
  }

  check_legacy_entry_in_file(pw_legacy, "/etc/passwd");
  check_legacy_entry_in_file(gr_legacy, "/etc/group");
  check_legacy_entry_in_file(sh_legacy, "/etc/shadow");

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

    if(!is_known_gid(user->pw_gid)) {
      check_add_findingf(unknowngid, "user %s has gid %u, which is unknown", user->pw_name, user->pw_gid);
    }

    if(user->pw_uid == 0) {
      if(strcmp(user->pw_name, "root") != 0) {
        check_add_findingf(root, "found another user with uid 0: %s", user->pw_name);
      }
      if(user->pw_gid != 0) {
        check_add_findingf(root_group, "root user has gid %d instead of 0", user->pw_gid);
      }
      continue;
    }

    if((user->pw_uid < 500) &&
          (strcmp(user->pw_name,"root") != 0) &&
          (strcmp(user->pw_name, "sync") != 0) &&
          (strcmp(user->pw_name, "shutdown") != 0) &&
          (strcmp(user->pw_name, "halt") != 0) &&
          (strcmp(user->pw_shell, "/sbin/nologin") != 0) &&
          (strcmp(user->pw_shell, "/bin/false") != 0)) {
      check_add_findingf(disablesysaccount, "system user %s with uid %u has shell %s. Expected: /sbin/nologin or /bin/false", user->pw_name, user->pw_uid, user->pw_shell);
    }

    if(!is_dialog_user(user))
      continue;

    if((shadow = getspnam(user->pw_name)) != NULL) {

      if(strcmp(shadow->sp_pwdp, "") == 0) {
        check_add_findingf(pw_empty, "user %s has an empty password", user->pw_name);
       }
      /* ignore users that will not be able to login with a password */
      if(shadow->sp_pwdp[0] != '!' && shadow->sp_pwdp[0] != '*') {
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
          check_add_findingf(pw_min, "user %s has minimum password set to %ld instead of 7 or more", user->pw_name, shadow->sp_min);
        }

        if(shadow->sp_warn == -1) {
          check_add_findingf(pw_warn, "user %s has password warning days disabled instead of 7 or more", user->pw_name);
        }
        else if(shadow->sp_warn < 7) {
          check_add_findingf(pw_warn, "user %s has password warning days set to %ld instead of 7 or more", user->pw_name, shadow->sp_warn);
        }
      }
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
            validate_homefile(dotfile_perm, user, direntry->d_name, 0022);
          }
        }
        closedir(homedir);

        validate_homefile(netrc_perm, user, ".netrc", 0077);
        validate_homefile(rhost_exist, user, ".rhosts", 0777);
        validate_homefile(forward_exist, user, ".forward", 0777);
        validate_homefile(netrc_exist, user, ".netrc", 0777);
      }
    }
  }
  endpwent();
  endspent();

  report_add_check(report, pw_max);
  report_add_check(report, pw_min);
  report_add_check(report, pw_warn);
  report_add_check(report, pw_empty);
  report_add_check(report, pw_legacy);
  report_add_check(report, gr_legacy);
  report_add_check(report, sh_legacy);
  report_add_check(report, disablesysaccount);
  report_add_check(report, root);
  report_add_check(report, root_group);
  report_add_check(report, home_perm);
  report_add_check(report, home_owner);
  report_add_check(report, dotfile_perm);
  report_add_check(report, netrc_perm);
  report_add_check(report, rhost_exist);
  report_add_check(report, forward_exist);
  report_add_check(report, netrc_exist);
  report_add_check(report, duplicate_uid);
  report_add_check(report, duplicate_gid);
  report_add_check(report, duplicate_pwname);
  report_add_check(report, duplicate_grname);
  report_add_check(report, inactive);
  report_add_check(report, unknowngid);
  return 0;
}
