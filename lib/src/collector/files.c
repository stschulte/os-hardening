#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/files.h>
#include <harden/util.h>

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mntent.h>
#include <pwd.h>
#include <grp.h>

#include <errno.h>

void traverse_dir(struct check* sticky, struct check* nouser, struct check* nogroup, const char* dir_name, dev_t devid) {
  DIR* d = opendir(dir_name);
  struct dirent *entry;

  if(!d) {
    perror("Cannot open directory");
    return;
  }

  while((entry = readdir(d)) != NULL) {
    // Skip .. and . directory
    if((strcmp(entry->d_name, "..") == 0) || (strcmp(entry->d_name, ".") == 0))
      continue;

    // construct the full path to use stat
    int path_length;
    char path[PATH_MAX];
    if(strcmp(dir_name, "/") == 0) {
      path_length = snprintf(path, PATH_MAX, "/%s", entry->d_name);
    }
    else {
      path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name, entry->d_name);
    }

    struct stat sb;
    lstat(path, &sb);

    if(is_known_uid(sb.st_uid) == 0) {
      check_add_findingf(nouser, "owner %d unknown: %s", sb.st_uid, path);
    }

    if(is_known_gid(sb.st_gid) == 0) {
      check_add_findingf(nogroup, "group %d unknown: %s", sb.st_gid, path);
    }


    // if stat tells us the entry is not a directory, skip
    if((sb.st_mode & S_IFMT) != S_IFDIR)
      continue;

    // if the directory is on another device, skip
    if(sb.st_dev != devid)
      continue;

    if((sb.st_mode & (S_IWOTH | S_ISVTX)) == S_IWOTH) {
      check_add_findingf(sticky, "no sticky set: %s", path);
    }

    traverse_dir(sticky, nouser, nogroup, path, sb.st_dev);
  }
  closedir(d);
}

static void verify_owner(struct check* check, const char* path) {
  struct passwd* owner;
  struct group* group;

  struct stat sb;
  lstat(path, &sb);

  owner = getpwuid(sb.st_uid);
  group = getgrgid(sb.st_gid);

  if(sb.st_uid != 0) {
    if(owner == NULL)
      check_add_findingf(check, "%s is owned by unknown user (uid %u) instead of root", path, sb.st_uid);
    else
      check_add_findingf(check, "%s is owned by user %s instead of root", path, owner->pw_name);
  }

  if(sb.st_gid != 0) {
    if(group == NULL)
      check_add_findingf(check, "%s is owned by unknown group (gid %u) instead of root", path, sb.st_gid);
    else
      check_add_findingf(check, "%s is owned by group %s instead of root", path, group->gr_name);
  }
}

static void verify_perm(struct check* check, const char* path, mode_t expected_mode) {
  struct stat sb;
  lstat(path, &sb);

  if((sb.st_mode & 07777) != expected_mode)
    check_add_findingf(check, "%s has incorrect permissions. Got: %03o. Expected: %03o", path, sb.st_mode & 07777, expected_mode);
}

int collector_files_evaluate(struct report* report) {
  struct check* stickybit = check_new("cis", "1.1.17", "Set Sticky Bit on All World-Writable Directories", CHECK_PASSED);

  struct check* perm_passwd = check_new("cis", "9.1.2", "Verify Permissions on /etc/passwd", CHECK_PASSED);
  struct check* perm_shadow = check_new("cis", "9.1.3", "Verify Permissions on /etc/shadow", CHECK_PASSED);
  struct check* perm_gshadow = check_new("cis", "9.1.4", "Verify Permissions on /etc/gshadow", CHECK_PASSED);
  struct check* perm_group = check_new("cis", "9.1.5", "Verify Permissions on /etc/group", CHECK_PASSED);

  struct check* owner_passwd = check_new("cis", "9.1.6", "Verify User/Group Ownership on /etc/passwd", CHECK_PASSED);
  struct check* owner_shadow = check_new("cis", "9.1.7", "Verify User/Group Ownership on /etc/shadow", CHECK_PASSED);
  struct check* owner_gshadow = check_new("cis", "9.1.8", "Verify User/Group Ownership on /etc/gshadow", CHECK_PASSED);
  struct check* owner_group = check_new("cis", "9.1.9", "Verify User/Group Ownership on /etc/group", CHECK_PASSED);

  struct check* nouser = check_new("cis", "9.1.11", "Find un-owned files and directories", CHECK_PASSED);
  struct check* nogroup = check_new("cis", "9.1.12", "Find un-grouped files and directories", CHECK_PASSED);

  verify_owner(owner_passwd, "/etc/passwd");
  verify_owner(owner_shadow, "/etc/shadow");
  verify_owner(owner_gshadow, "/etc/gshadow");
  verify_owner(owner_group, "/etc/group");

  verify_perm(perm_passwd, "/etc/passwd", 0644);
  verify_perm(perm_shadow, "/etc/shadow", 0000);
  verify_perm(perm_gshadow, "/etc/gshadow", 0000);
  verify_perm(perm_group, "/etc/group", 0644);

  FILE* f = setmntent("/proc/self/mounts", "r");
  struct mntent *mount;

  while((mount = getmntent(f)) != NULL) {
    if(strcmp(mount->mnt_type, "autofs") == 0
            || strcmp(mount->mnt_type, "proc") == 0
            || strcmp(mount->mnt_type, "subfs") == 0
            || strcmp(mount->mnt_type, "debugfs") == 0
            || strcmp(mount->mnt_type, "devpts") == 0
            || strcmp(mount->mnt_type, "fusectl") == 0
            || strcmp(mount->mnt_type, "mqueue") == 0
            || strcmp(mount->mnt_type, "rpc_pipefs") == 0
            || strcmp(mount->mnt_type, "sysfs") == 0
            || strcmp(mount->mnt_type, "devfs") == 0
            || strcmp(mount->mnt_type, "kernfs") == 0
            || strcmp(mount->mnt_type, "ignore") == 0)
      continue;

    if((strchr(mount->mnt_fsname, ':') != NULL) || (strncmp(mount->mnt_fsname, "//", 2) == 0 && strcmp(mount->mnt_type, "cifs") == 0))
      continue;

    //printf("collector/files: Checking files on %s\n", mount->mnt_dir);

    struct stat sb;
    lstat(mount->mnt_dir, &sb);
    traverse_dir(stickybit, nouser, nogroup, mount->mnt_dir, sb.st_dev);
  }
  endmntent(f);

  report_add_check(report, stickybit);
  report_add_check(report, nouser);
  report_add_check(report, nogroup);
  report_add_check(report, perm_passwd);
  report_add_check(report, perm_shadow);
  report_add_check(report, perm_gshadow);
  report_add_check(report, perm_group);
  report_add_check(report, owner_passwd);
  report_add_check(report, owner_shadow);
  report_add_check(report, owner_gshadow);
  report_add_check(report, owner_group);
  return 0;
}
