#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <harden/util.h>

#define UID_MALLOC_CHUNK 100
#define GID_MALLOC_CHUNK 100

static uid_t* uids = NULL;
static gid_t* gids = NULL;
static long int nuids = 0;
static long int ngids = 0;

void init_util(void) {
  get_known_uids();
  get_known_gids();
}

int compare_uid(const void* a, const void* b) {
  uid_t uid_a = *( (uid_t*)a);
  uid_t uid_b = *( (uid_t*)b);
  if(uid_a == uid_b)
    return 0;
  else if(uid_a < uid_b)
    return -1;
  else
    return 1;
}

int compare_gid(const void* a, const void* b) {
  gid_t gid_a = *( (gid_t*)a);
  gid_t gid_b = *( (gid_t*)b);
  if(gid_a == gid_b)
    return 0;
  else if(gid_a < gid_b)
    return -1;
  else
    return 1;
}

void get_known_uids(void) {
  struct passwd* user;

  setpwent();
  for(nuids=0; (user = getpwent()) != NULL; nuids++) {
    if(nuids % UID_MALLOC_CHUNK == 0) {
      uids = realloc(uids, (nuids+UID_MALLOC_CHUNK)*sizeof(uid_t));
    }
    uids[nuids] = user->pw_uid;
  }
  uids = realloc(uids, (nuids)*sizeof(uid_t));
  endpwent();

  qsort(uids, nuids, sizeof(uid_t), compare_uid);
}

void get_known_gids(void) {
  struct group* group;

  setgrent();
  for(ngids=0; (group = getgrent()) != NULL; ngids++) {
    if(ngids % GID_MALLOC_CHUNK == 0) {
      gids = realloc(gids, (ngids+GID_MALLOC_CHUNK)*sizeof(gid_t));
    }
    gids[ngids] = group->gr_gid;
  }
  gids = realloc(gids, (ngids)*sizeof(gid_t));
  endgrent();

  qsort(gids, ngids, sizeof(gid_t), compare_gid);
}

int is_dialog_user(struct passwd* user) {
  if((strcmp(user->pw_shell, "/sbin/nologin") == 0) ||
    (strcmp(user->pw_shell, "/bin/false") == 0) ||
    (strcmp(user->pw_shell, "/bin/sync") == 0) ||
    (strcmp(user->pw_shell, "/sbin/halt") == 0) ||
    (strcmp(user->pw_shell, "/sbin/shutdown") == 0))
    return 0;

  return 1;
}

int is_known_uid(uid_t uid) {
  for(long i=0; i < nuids; i++) {
    if(uids[i] == uid)
      return 1;
    else if(uids[i] > uid)
      return 0;
  }
  return 0;
}

int is_known_gid(gid_t gid) {
  for(long i=0; i < ngids; i++) {
    if(gids[i] == gid)
      return 1;
    else if(gids[i] > gid)
      return 0;
  }
  return 0;
}
