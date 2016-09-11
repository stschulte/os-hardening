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

#define USER_MALLOC_CHUNK 100
#define GROUP_MALLOC_CHUNK 100

int compare_users_by_uid(const void* a, const void *b) {
  struct passwd* user_a = *( (struct passwd**)a );
  struct passwd* user_b = *( (struct passwd**)b );
  if(user_a->pw_uid == user_b->pw_uid)
    return 0;
  else if(user_a->pw_uid < user_b->pw_uid)
    return -1;
  else
    return 1;
}

int compare_users_by_name(const void* a, const void *b) {
  struct passwd* user_a = *( (struct passwd**)a );
  struct passwd* user_b = *( (struct passwd**)b );
  return strcmp(user_a->pw_name, user_b->pw_name);
}

int compare_groups_by_name(const void* a, const void* b) {
  struct group* group_a = *( (struct group**)a );
  struct group* group_b = *( (struct group**)b );
  return strcmp(group_a->gr_name, group_b->gr_name);
}

int compare_groups_by_gid(const void* a, const void* b) {
  struct group* group_a = *( (struct group**)a );
  struct group* group_b = *( (struct group**)b );
  if(group_a->gr_gid == group_b->gr_gid)
    return 0;
  else if(group_a->gr_gid < group_b->gr_gid)
    return -1;
  else
    return 1;
}

void check_user_duplicates(struct check* duplicate_uid, struct check* duplicate_pwname) {
  struct passwd* user;

  int user_count = 0;
  struct passwd* available_users = NULL;
  struct passwd** available_users_by_name = NULL;
  struct passwd** available_users_by_uid = NULL;

  /* collect all users */
  setpwent();
  for(user_count = 0; (user = getpwent()) != NULL; user_count++) {
    if(user_count % USER_MALLOC_CHUNK == 0) {
      available_users = realloc(available_users, (user_count + USER_MALLOC_CHUNK)*sizeof(struct passwd));
    }
    available_users[user_count].pw_name = strdup(user->pw_name);
    available_users[user_count].pw_uid = user->pw_uid;
  }
  endpwent();

  /* create two arrays that are sorted by name and gid */
  available_users_by_name = malloc(user_count * sizeof(struct passwd*));
  available_users_by_uid = malloc(user_count * sizeof(struct passwd*));
  for(int i=0; i < user_count; i++) {
    available_users_by_name[i] = &available_users[i];
    available_users_by_uid[i] = &available_users[i];
  }
  qsort(available_users_by_name, user_count, sizeof(struct passwd*), compare_users_by_name);
  qsort(available_users_by_uid, user_count, sizeof(struct passwd*), compare_users_by_uid);

  for(int i=1; i < user_count; i++) {
    struct passwd* a;
    struct passwd* b;

    a = available_users_by_uid[i-1];
    b = available_users_by_uid[i];
    if(a->pw_uid == b->pw_uid) {
      check_add_findingf(duplicate_uid, "user %s and %s have the same uid %u", a->pw_name, b->pw_name, a->pw_uid);
    }

    a = available_users_by_name[i-1];
    b = available_users_by_name[i];
    if(strcmp(a->pw_name, b->pw_name) == 0) {
      check_add_findingf(duplicate_pwname, "user %s has two uids %u and %u", a->pw_name, a->pw_uid, b->pw_uid);
    }
  }

  for(int i=0; i < user_count; i++)
    free(available_users[i].pw_name);

  free(available_users);
  free(available_users_by_uid);
  free(available_users_by_name);
}
void check_group_duplicates(struct check* duplicate_gid, struct check* duplicate_grname) {
  struct group* group;

  int group_count = 0;
  struct group* available_groups = NULL;
  struct group** available_groups_by_name = NULL;
  struct group** available_groups_by_gid = NULL;

  /* collect all groups */
  setgrent();
  for(group_count = 0; (group = getgrent()) != NULL; group_count++) {
    if(group_count % GROUP_MALLOC_CHUNK == 0) {
      available_groups = realloc(available_groups, (group_count + GROUP_MALLOC_CHUNK)*sizeof(struct group));
    }
    available_groups[group_count].gr_name = strdup(group->gr_name);
    available_groups[group_count].gr_gid = group->gr_gid;
  }
  endgrent();

  /* create two arrays that are sorted by name and gid */
  available_groups_by_name = malloc(group_count * sizeof(struct group*));
  available_groups_by_gid = malloc(group_count * sizeof(struct group*));
  for(int i=0; i < group_count; i++) {
    available_groups_by_name[i] = &available_groups[i];
    available_groups_by_gid[i] = &available_groups[i];
  }
  qsort(available_groups_by_name, group_count, sizeof(struct group*), compare_groups_by_name);
  qsort(available_groups_by_gid, group_count, sizeof(struct group*), compare_groups_by_gid);

  for(int i=1; i < group_count; i++) {
    struct group* a;
    struct group* b;

    a = available_groups_by_gid[i-1];
    b = available_groups_by_gid[i];
    if(a->gr_gid == b->gr_gid) {
      check_add_findingf(duplicate_gid, "group %s and %s have the same gid %u", a->gr_name, b->gr_name, a->gr_gid);
    }

    a = available_groups_by_name[i-1];
    b = available_groups_by_name[i];
    if(strcmp(a->gr_name, b->gr_name) == 0) {
      check_add_findingf(duplicate_grname, "group %s has two gids %u and %u", a->gr_name, a->gr_gid, b->gr_gid);
    }
  }

  for(int i=0; i < group_count; i++)
    free(available_groups[i].gr_name);

  free(available_groups);
  free(available_groups_by_gid);
  free(available_groups_by_name);
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

int collector_user_evaluate(struct report* report) {
  struct passwd* user;
  struct spwd* shadow;
  struct stat sb_homedir;
  struct stat sb_file;
  struct passwd* owner;

  DIR* homedir;
  struct dirent* direntry;
  char* file;

  struct check* pw_max = check_new("cis", "7.1.1", "Set Password Expiration Days", CHECK_PASSED);
  struct check* pw_min = check_new("cis", "7.1.2", "Set Password Change Minimum Number of Day", CHECK_PASSED);
  struct check* pw_warn = check_new("cis", "7.1.3", "Set Password Expiring Warning Days", CHECK_PASSED);
  struct check* root_group = check_new("cis", "7.3", "Set Default Group for root Account", CHECK_PASSED);

  struct check* home_perm = check_new("cis", "9.2.7", "Check Permissions on User Home Directories", CHECK_PASSED);
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

  check_user_duplicates(duplicate_uid, duplicate_pwname);
  check_group_duplicates(duplicate_gid, duplicate_grname);

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

    if((shadow = getspnam(user->pw_name)) != NULL) {
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
          check_add_findingf(pw_min, "user %s has minimum password set to %ld instead of 7 or more", user->pw_name, shadow->sp_max);
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
  return 0;
}
