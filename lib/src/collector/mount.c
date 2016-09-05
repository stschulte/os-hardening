#include <stdlib.h>
#include <stdio.h>
#include <mntent.h>
#include <string.h>

#include <harden/report.h>
#include <harden/check.h>
#include <harden/collector/mount.h>

int collector_mount_evaluate(struct report* report) {
  struct check* fs_tmp = check_new("cis", "1.1.1", "Create Separate Partition for /tmp", CHECK_FAILED);
  struct check* fs_tmp_nodev = check_new("cis", "1.1.2", "Set nodev option for /tmp", CHECK_FAILED);
  struct check* fs_tmp_nosuid = check_new("cis", "1.1.3", "Set nosuid option for /tmp", CHECK_FAILED);
  struct check* fs_tmp_noexec = check_new("cis", "1.1.4", "Set noexec option for /tmp", CHECK_FAILED);
  struct check* fs_var = check_new("cis", "1.1.5", "Create Separate Partition for /var", CHECK_FAILED);
  struct check* fs_var_tmp_bind = check_new("cis", "1.1.6", "Bind Mount /var/tmp to /tmp", CHECK_FAILED);
  struct check* fs_var_log = check_new("cis", "1.1.7", "Create Separate Partition for /var/log", CHECK_FAILED);
  struct check* fs_var_log_audit = check_new("cis", "1.1.8", "Create Separate Partition for /var/log/audit", CHECK_FAILED);
  struct check* fs_home = check_new("cis", "1.1.9", "Create Separate Partition for /home", CHECK_FAILED);
  struct check* fs_home_nodev = check_new("cis", "1.1.10", "Add nodev Option to /home", CHECK_FAILED);
  struct check* fs_shm_nodev = check_new("cis", "1.1.14", "Add nodev Option to /dev/shm", CHECK_FAILED);
  struct check* fs_shm_nosuid = check_new("cis", "1.1.15", "Add nosuid Option to /dev/shm", CHECK_FAILED);
  struct check* fs_shm_noexec = check_new("cis", "1.1.16", "Add noexec Option to /dev/shm", CHECK_FAILED);

  struct mntent *entry;
  FILE *f;

  f = setmntent("/proc/self/mounts", "r");
  if(f == NULL) {
    perror("setmntent");
    return(1);
  }

  while((entry = getmntent(f)) != NULL) {
    if(strcmp(entry->mnt_dir, "/tmp") == 0) {
      fs_tmp->result = CHECK_PASSED;

      if(hasmntopt(entry, "nodev"))
        fs_tmp_nodev->result = CHECK_PASSED;
      else
        check_add_findingf(fs_tmp_nodev, "/tmp is mounted with mount options %s. Expected to include: nodev", entry->mnt_opts);

      if(hasmntopt(entry, "nosuid"))
        fs_tmp_nosuid->result = CHECK_PASSED;
      else
        check_add_findingf(fs_tmp_nosuid, "/tmp is mounted with mount options %s. Expected to include: nosuid", entry->mnt_opts);

      if(hasmntopt(entry, "noexec"))
        fs_tmp_noexec->result = CHECK_PASSED;
      else
        check_add_findingf(fs_tmp_noexec, "/tmp is mounted with mount options %s. Expected to include: noexec", entry->mnt_opts);
    }
    else if(strcmp(entry->mnt_dir, "/var") == 0) {
      fs_var->result = CHECK_PASSED;
    }
    else if(strcmp(entry->mnt_dir, "/var/tmp") == 0) {
      if(strcmp(entry->mnt_fsname, "/tmp") == 0)
        fs_var_tmp_bind->result = CHECK_PASSED;
      else
        check_add_findingf(fs_var_tmp_bind, "/var/tmp should be a bind mount of /tmp, but device is %s", entry->mnt_fsname);
    }
    else if(strcmp(entry->mnt_dir, "/var/log") == 0) {
      fs_var_log->result = CHECK_PASSED;
    }
    else if(strcmp(entry->mnt_dir, "/var/log/audit") == 0) {
      fs_var_log_audit->result = CHECK_PASSED;
    }
    else if(strcmp(entry->mnt_dir, "/home") == 0) {
      fs_home->result = CHECK_PASSED;
      if(hasmntopt(entry, "nodev"))
        fs_home_nodev->result = CHECK_PASSED;
      else
        check_add_findingf(fs_home_nodev, "/home is mounted with mount options %s. Expected to include: nodev", entry->mnt_opts);
    }
    else if(strcmp(entry->mnt_dir, "/dev/shm") == 0) {
      if(hasmntopt(entry, "nodev"))
        fs_shm_nodev->result = CHECK_PASSED;
      else
        check_add_findingf(fs_shm_nodev, "/dev/shm is mounted with mount options %s. Expected to include: nodev", entry->mnt_opts);

      if(hasmntopt(entry, "nosuid"))
        fs_shm_nosuid->result = CHECK_PASSED;
      else
        check_add_findingf(fs_shm_nosuid, "/dev/shm is mounted with mount options %s. Expected to include: nosuid", entry->mnt_opts);

      if(hasmntopt(entry, "noexec"))
        fs_shm_noexec->result = CHECK_PASSED;
      else
        check_add_findingf(fs_shm_noexec, "/dev/shm is mounted with mount options %s. Expected to include: noexec", entry->mnt_opts);
    }
  }
  endmntent(f);

  if(fs_tmp->result == CHECK_FAILED) {
    check_add_finding(fs_tmp, "/tmp is no separate partition");
    check_add_finding(fs_tmp_noexec, "requirement not met because /tmp is no separate partition");
    check_add_finding(fs_tmp_nosuid, "requirement not met because /tmp is no separate partition");
    check_add_finding(fs_tmp_nodev, "requirement not met because /tmp is no separate partition");
  }

  if(fs_var->result == CHECK_FAILED) {
    check_add_finding(fs_tmp, "/var is no separate partition");
  }

  if(fs_var_log->result == CHECK_FAILED)
    check_add_finding(fs_var_log, "/var/log is no separate partition");
  if(fs_var_log_audit->result == CHECK_FAILED)
    check_add_finding(fs_var_log_audit, "/var/log/audit is no separate partition");
  if(fs_home->result == CHECK_FAILED)
    check_add_finding(fs_home, "/home is no separate partition");

  report_add_check(report, fs_tmp);
  report_add_check(report, fs_tmp_nodev);
  report_add_check(report, fs_tmp_nosuid);
  report_add_check(report, fs_tmp_noexec);
  report_add_check(report, fs_var);
  report_add_check(report, fs_var_tmp_bind);
  report_add_check(report, fs_var_log);
  report_add_check(report, fs_var_log_audit);
  report_add_check(report, fs_home);
  report_add_check(report, fs_home_nodev);
  report_add_check(report, fs_shm_nodev);
  report_add_check(report, fs_shm_nosuid);
  report_add_check(report, fs_shm_noexec);

  return 0;
}
