#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <harden/util.h>
#include <harden/report.h>
#include <harden/check.h>

#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <errno.h>

#define CACHE_MALLOC_CHUNK 500

static uid_t* uids = NULL;
static gid_t* gids = NULL;

static struct passwd* users = NULL;
static struct passwd** users_by_name = NULL;
static struct passwd** users_by_uid = NULL;

static struct spwd*  shadows = NULL;
static struct spwd** shadows_by_name = NULL;

static struct group* groups = NULL;
static struct group** groups_by_name = NULL;
static struct group** groups_by_gid = NULL;

static int user_count = 0;
static int group_count = 0;
static int shadow_count = 0;


void util_init(void) {
  user_count = cache_known_users();
  group_count = cache_known_groups();
  shadow_count = cache_known_shadows();
  printf("init: cached %d users, %d shadow information and %d groups\n", user_count, shadow_count, group_count);
}

void util_clean(void) {
  free(users_by_name);
  free(users_by_uid);
  free(shadows_by_name);
  free(groups_by_name);
  free(groups_by_gid);

  for(int i=0; i < user_count; i++) {
    free(users[i].pw_name);
    free(users[i].pw_passwd);
    free(users[i].pw_gecos);
    free(users[i].pw_dir);
    free(users[i].pw_shell);
  }

  for(int i=0; i < shadow_count; i++) {
    free(shadows[i].sp_namp);
    free(shadows[i].sp_pwdp);
  }

  for(int i=0; i < group_count; i++)
    free(groups[i].gr_name);

  free(users);
  free(shadows);
  free(groups);

  free(uids);
  free(gids);
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

int compare_shadows_by_name(const void* a, const void *b) {
  struct spwd* user_a = *( (struct spwd**)a );
  struct spwd* user_b = *( (struct spwd**)b );
  return strcmp(user_a->sp_namp, user_b->sp_namp);
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

int compare_groups_by_name(const void* a, const void* b) {
  struct group* group_a = *( (struct group**)a );
  struct group* group_b = *( (struct group**)b );
  return strcmp(group_a->gr_name, group_b->gr_name);
}

int cache_known_shadows(void) {
  struct spwd* user;
  int count;

  setspent();
  for(count = 0; (user = getspent()) != NULL; count++) {
    if(count % CACHE_MALLOC_CHUNK == 0) {
      shadows = realloc(shadows, (count + CACHE_MALLOC_CHUNK)*sizeof(struct spwd));
    }

    shadows[count].sp_namp = strdup(user->sp_namp);
    shadows[count].sp_pwdp = strdup(user->sp_pwdp);
    shadows[count].sp_lstchg = user->sp_lstchg;
    shadows[count].sp_min = user->sp_min;
    shadows[count].sp_warn = user->sp_warn;
    shadows[count].sp_inact = user->sp_inact;
    shadows[count].sp_expire = user->sp_expire;
    shadows[count].sp_flag = user->sp_flag;
  }
  endspent();

  shadows = realloc(shadows, count*sizeof(struct spwd));
  shadows_by_name = malloc(count * sizeof(struct spwd*));

  for(int i=0; i < count; i++) {
    shadows_by_name[i] = &shadows[i];
  }

  qsort(shadows_by_name, count, sizeof(struct spwd*), compare_shadows_by_name);
  return count;
}

int cache_known_users(void) {
  struct passwd* user;
  int count;

  setpwent();
  for(count = 0; (user = getpwent()) != NULL; count++) {
    if(count % CACHE_MALLOC_CHUNK == 0) {
      uids  = realloc(uids,  (count + CACHE_MALLOC_CHUNK)*sizeof(uid_t));
      users = realloc(users, (count + CACHE_MALLOC_CHUNK)*sizeof(struct passwd));
    }
    uids[count] = user->pw_uid;

    users[count].pw_name = strdup(user->pw_name);
    users[count].pw_passwd = strdup(user->pw_passwd);
    users[count].pw_uid = user->pw_uid;
    users[count].pw_gid = user->pw_gid;
    users[count].pw_gecos = strdup(user->pw_gecos);
    users[count].pw_dir = strdup(user->pw_dir);
    users[count].pw_shell = strdup(user->pw_shell);
  }
  endpwent();

  uids  = realloc(uids,  count * sizeof(uid_t));
  users = realloc(users, count * sizeof(struct passwd));

  users_by_name = malloc(count * sizeof(struct passwd*));
  users_by_uid = malloc(count * sizeof(struct passwd*));

  for(int i=0; i < count; i++) {
    users_by_name[i] = &users[i];
    users_by_uid[i] = &users[i];
  }

  qsort(uids, count, sizeof(uid_t), compare_uid);
  qsort(users_by_name, count, sizeof(struct passwd*), compare_users_by_name);
  qsort(users_by_uid, count, sizeof(struct passwd*), compare_users_by_uid);

  return count;
}

int cache_known_groups(void) {
  struct group* group;
  int count;

  setgrent();
  for(count = 0; (group = getgrent()) != NULL; count++) {
    if(group_count % CACHE_MALLOC_CHUNK == 0) {
      gids   = realloc(gids,   (count + CACHE_MALLOC_CHUNK)*sizeof(gid_t));
      groups = realloc(groups, (count + CACHE_MALLOC_CHUNK)*sizeof(struct group));
    }
    gids[count] = group->gr_gid;
    groups[count].gr_name = strdup(group->gr_name);
    groups[count].gr_gid = group->gr_gid;
  }
  endgrent();

  gids   = realloc(gids,   count * sizeof(gid_t));
  groups = realloc(groups, count * sizeof(struct group));

  groups_by_name = malloc(count * sizeof(struct group*));
  groups_by_gid = malloc(count * sizeof(struct group*));

  for(int i=0; i < count; i++) {
    groups_by_name[i] = &groups[i];
    groups_by_gid[i] = &groups[i];
  }

  qsort(gids, count, sizeof(gid_t), compare_gid);
  qsort(groups_by_name, count, sizeof(struct group*), compare_groups_by_name);
  qsort(groups_by_gid, count, sizeof(struct group*), compare_groups_by_gid);

  return count;
}

int get_cached_users(struct passwd*** ptr_by_name, struct passwd*** ptr_by_uid) {
  *ptr_by_name = users_by_name;
  *ptr_by_uid = users_by_uid;
  return user_count;
}

int get_cached_groups(struct group*** ptr_by_name, struct group*** ptr_by_gid) {
  *ptr_by_name = groups_by_name;
  *ptr_by_gid = groups_by_gid;
  return group_count;
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
  if(bsearch(&uid, uids, user_count, sizeof(uid_t), compare_uid) == NULL)
    return 0;

  return 1;
}

int is_known_gid(gid_t gid) {
  if(bsearch(&gid, gids, group_count, sizeof(gid_t), compare_gid) == NULL)
    return 0;

  return 1;
}

struct passwd* cached_getpwuid(uid_t uid) {
  struct passwd match = { NULL, NULL, uid, 0, NULL, NULL, NULL };
  struct passwd* key = &match;
  struct passwd** result = bsearch(&key, users_by_uid, user_count, sizeof(struct passwd*), compare_users_by_uid);

  if(result == NULL)
    return NULL;

  return *result;
}

void report_add_new_check_perm(struct report* r, const char* collection, const char* id, const char* summary, const char* path, const char* expected_owner, const char* expected_group, mode_t expected_mode, enum scope flags) {
  struct check* c = check_new(collection, id, summary, CHECK_PASSED);
  struct stat sb;
  struct passwd* owner;
  struct group* group;

  if(stat(path, &sb) >=0) {
    if(flags & CHECK_MODE) {
      if((sb.st_mode & 07777) != expected_mode) {
        check_add_findingf(c, "%s has incorrect permissions. Got: %03o. Expected: %03o", path, sb.st_mode & 07777, expected_mode);
      }
    }
    if(flags & CHECK_OWNER) {
      if((owner = getpwuid(sb.st_uid)) == NULL) {
        check_add_findingf(c, "%s is owned by unknown user with uid %u. Expected: %s", path, sb.st_uid, expected_owner);
      }
      else if(strcmp(expected_owner, owner->pw_name) != 0) {
        check_add_findingf(c, "%s is owned by user %s. Expected: %s", path, owner->pw_name, expected_owner);
      }
    }
   if(flags & CHECK_GROUP) {
      if((group = getgrgid(sb.st_gid)) == NULL) {
        check_add_findingf(c, "%s is owned by unknown group with gid %u. Expected: %s", path, sb.st_gid, expected_group);
      }
      else if(strcmp(expected_group, group->gr_name) != 0) {
        check_add_findingf(c, "%s is owned by group %s. Expected: %s", path, group->gr_name, expected_group);
      }
    }
  }
  else if(errno == ENOENT) {
    if(flags & CHECK_EXIST) {
      check_add_findingf(c, "%s was not found", path);
    }
  }
  else {
    check_add_findingf(c, "error to stat %s: %s", path, strerror(errno));
  }

  report_add_check(r, c);
}
