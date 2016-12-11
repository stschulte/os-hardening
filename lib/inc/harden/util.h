#ifndef HARDEN_UTIL_H
#define HARDEN_UTIL_H

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <harden/report.h>

enum scope {
  CHECK_EXIST = 1,
  CHECK_OWNER = 2,
  CHECK_GROUP = 4,
  CHECK_MODE  = 8,
  CHECK_ALL   = 15,
};

void util_init(void);
void util_clean(void);

int cache_known_users(void);
int cache_known_groups(void);
int cache_known_shadows(void);

int is_dialog_user(struct passwd* user);
int is_known_uid(uid_t uid);
int is_known_gid(gid_t gid);

int get_cached_users(struct passwd*** ptr_by_name, struct passwd*** ptr_by_uid);
int get_cached_groups(struct group*** ptr_by_name, struct group*** ptr_by_gid);

struct passwd* cached_getpwuid(uid_t uid);

void report_add_new_check_perm(struct report* r, const char* collection, const char* id, const char* summary, const char* path, const char* expected_owner, const char* expected_group, mode_t expected_mode, enum scope flags);
#endif
