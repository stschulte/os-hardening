#ifndef HARDEN_UTIL_H
#define HARDEN_UTIL_H

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

void util_init(void);
void util_clean(void);

int cache_known_users(void);
int cache_known_groups(void);

int is_dialog_user(struct passwd* user);
int is_known_uid(uid_t uid);
int is_known_gid(gid_t gid);

int get_cached_users(struct passwd*** ptr_by_name, struct passwd*** ptr_by_uid);
int get_cached_groups(struct group*** ptr_by_name, struct group*** ptr_by_gid);

#endif
