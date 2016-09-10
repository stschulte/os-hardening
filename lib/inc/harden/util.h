#ifndef HARDEN_UTIL_H
#define HARDEN_UTIL_H

#include <sys/types.h>
#include <pwd.h>

void util_init(void);
void util_clean(void);
void cache_known_uids(void);
void cache_known_gids(void);

int is_dialog_user(struct passwd* user);
int is_known_uid(uid_t uid);
int is_known_gid(gid_t gid);

#endif
