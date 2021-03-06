#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/files.h>
#include <harden/util.h>

#include <dirent.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mntent.h>
#include <pwd.h>
#include <grp.h>

#include <errno.h>

static long files = 0;

void traverse_dir(struct check* sticky, struct check* nouser, struct check* nogroup, const char* dir_name, dev_t devid) {
  DIR* d = opendir(dir_name);
  struct dirent *entry;

  if(!d) {
    fprintf(stderr, "Cannot open directory %s: %s\n", dir_name, strerror(errno));
    return;
  }

  while(((entry = readdir(d)) != NULL) && ((sticky->result & nouser->result & nogroup->result & CHECK_MAX_FINDINGS) == 0)) {
    // Skip .. and . directory
    if((strcmp(entry->d_name, "..") == 0) || (strcmp(entry->d_name, ".") == 0))
      continue;

    // construct the full path to show in findings
    int path_length;
    char path[PATH_MAX];
    if(strcmp(dir_name, "/") == 0) {
      path_length = snprintf(path, PATH_MAX, "/%s", entry->d_name);
    }
    else {
      path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name, entry->d_name);
    }

    files++;

    struct stat sb;
    fstatat(dirfd(d), entry->d_name, &sb, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT);

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

void verify_os_info(struct check* c, const char* file) {
  FILE* stream;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;

  stream = fopen(file, "r");
  if(stream == NULL)
    return;

  while((read = getline(&line, &len, stream)) != -1) {
    if(strstr(line, "\\m") != NULL)
      check_add_findingf(c, "%s contains \"\\m\" to print machine architecture", file);
    if(strstr(line, "\\r") != NULL)
      check_add_findingf(c, "%s contains \"\\r\" to print operating system release", file);
    if(strstr(line, "\\s") != NULL)
      check_add_findingf(c, "%s contains \"\\s\" to print operating system name", file);
    if(strstr(line, "\\v") != NULL)
      check_add_findingf(c, "%s contains \"\\v\" to print operating system version", file);
  }

  free(line);
  fclose(stream);
}


int collector_files_evaluate(struct report* report, enum collector_flags flags) {
  struct check* stickybit = check_new("cis", "1.1.17", "Set Sticky Bit on All World-Writable Directories", CHECK_PASSED);

  struct check* nouser = check_new("cis", "9.1.11", "Find un-owned files and directories", CHECK_PASSED);
  struct check* nogroup = check_new("cis", "9.1.12", "Find un-grouped files and directories", CHECK_PASSED);
  struct check* banner = check_new("cis", "8.1", "Set Warning Banner for Standard Login Services", CHECK_PASSED);
  struct check* banneros = check_new("cis", "8.2", "Remove OS Information from Login Warning Banners", CHECK_PASSED);

  report_add_new_check_perm(report, "cis", "9.1.2", "Verify Permissions on /etc/passwd", "/etc/passwd", NULL, NULL, 0644, CHECK_EXIST | CHECK_MODE);
  report_add_new_check_perm(report, "cis", "9.1.3", "Verify Permissions on /etc/shadow", "/etc/shadow", NULL, NULL, 0000, CHECK_EXIST | CHECK_MODE);
  report_add_new_check_perm(report, "cis", "9.1.4", "Verify Permissions on /etc/gshadow", "/etc/gshadow", NULL, NULL, 0000, CHECK_EXIST | CHECK_MODE);
  report_add_new_check_perm(report, "cis", "9.1.5", "Verify Permissions on /etc/group", "/etc/group", NULL, NULL, 0644, CHECK_EXIST | CHECK_MODE);

  report_add_new_check_perm(report, "cis", "9.1.6", "Verify User/Group Ownership on /etc/passwd", "/etc/passwd", "root", "root", 0, CHECK_EXIST | CHECK_OWNER | CHECK_GROUP);
  report_add_new_check_perm(report, "cis", "9.1.7", "Verify User/Group Ownership on /etc/shadow", "/etc/shadow", "root", "root", 0, CHECK_EXIST | CHECK_OWNER | CHECK_GROUP);
  report_add_new_check_perm(report, "cis", "9.1.8", "Verify User/Group Ownership on /etc/gshadow", "/etc/gshadow", "root", "root", 0, CHECK_EXIST | CHECK_OWNER | CHECK_GROUP);
  report_add_new_check_perm(report, "cis", "9.1.9", "Verify User/Group Ownership on /etc/group", "/etc/group", "root", "root", 0, CHECK_EXIST | CHECK_OWNER | CHECK_GROUP);

  report_add_new_check_perm(report, "cis", "6.1.3", "Set User/Group Owner and Permission on /etc/anacrontab", "/etc/anacrontab", "root", "root", 0600, CHECK_ALL);
  report_add_new_check_perm(report, "cis", "6.1.4", "Set User/Group Owner and Permission on /etc/crontab", "/etc/crontab", "root", "root", 0600, CHECK_ALL);
  report_add_new_check_perm(report, "cis", "6.1.5", "Set User/Group Owner and Permission on /etc/cron.hourly", "/etc/cron.hourly", "root", "root", 0700, CHECK_ALL);
  report_add_new_check_perm(report, "cis", "6.1.6", "Set User/Group Owner and Permission on /etc/cron.daily", "/etc/cron.daily", "root", "root", 0700, CHECK_ALL);
  report_add_new_check_perm(report, "cis", "6.1.7", "Set User/Group Owner and Permission on /etc/cron.weekly", "/etc/cron.weekly", "root", "root", 0700, CHECK_ALL);
  report_add_new_check_perm(report, "cis", "6.1.8", "Set User/Group Owner and Permission on /etc/cron.monthly", "/etc/cron.monthly", "root", "root", 0700, CHECK_ALL);
  report_add_new_check_perm(report, "cis", "6.1.9", "Set User/Group Owner and Permission on /etc/cron.d", "/etc/cron.d", "root", "root", 0700, CHECK_ALL);

  report_add_new_check_perm(report, "cis", "4.5.3", "Verify Permissions on /etc/hosts.allow", "/etc/hosts.allow", "root", "root", 0644, CHECK_OWNER | CHECK_GROUP | CHECK_MODE);
  report_add_new_check_perm(report, "cis", "4.5.5", "Verify Permissions on /etc/hosts.deny", "/etc/hosts.deny", "root", "root", 0644, CHECK_OWNER | CHECK_GROUP | CHECK_MODE);


  if(access("/etc/motd", F_OK) != 0)
    check_add_findingf(banner, "file /etc/motd was not found");
  if(access("/etc/issue", F_OK) != 0)
    check_add_findingf(banner, "file /etc/issue was not found");
  if(access("/etc/issue.net", F_OK) != 0)
    check_add_findingf(banner, "file /etc/issue.net was not found");

  verify_os_info(banneros, "/etc/issue");
  verify_os_info(banneros, "/etc/motd");
  verify_os_info(banneros, "/etc/issue.net");

  struct mntent *mount;

  files = 0;

  if(flags & COLLECTOR_FAST) {
    stickybit->result = CHECK_SKIPPED;
    nouser->result = CHECK_SKIPPED;
    nogroup->result = CHECK_SKIPPED;
  }
  else {
    FILE* f = setmntent("/proc/self/mounts", "r");
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
              || strcmp(mount->mnt_type, "ignore") == 0
              || strcmp(mount->mnt_type, "rootfs") == 0
              || strcmp(mount->mnt_type, "cgroup") == 0)
        continue;

      if((strchr(mount->mnt_fsname, ':') != NULL) || (strncmp(mount->mnt_fsname, "//", 2) == 0 && strcmp(mount->mnt_type, "cifs") == 0))
        continue;

      printf("collector/files: Checking files on %s\n", mount->mnt_dir);

      struct stat sb;
      lstat(mount->mnt_dir, &sb);
      traverse_dir(stickybit, nouser, nogroup, mount->mnt_dir, sb.st_dev);
    }
    endmntent(f);
  }

  printf("collector/files: Checked %ld files\n", files);
  report_add_check(report, stickybit);
  report_add_check(report, nouser);
  report_add_check(report, nogroup);
  report_add_check(report, banner);
  report_add_check(report, banneros);
  return 0;
}
