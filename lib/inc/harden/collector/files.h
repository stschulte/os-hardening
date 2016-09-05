#ifndef HARDEN_COLLECTOR_FILES_H
#define HARDEN_COLLECTOR_FILES_H

#include <sys/types.h>

int is_known_uid(uid_t uid);
void traverse_dir(struct check* sticky, struct check* nouser, struct check* nogroup, const char* dir_name, dev_t devid);
int collector_files_evaluate(struct report* report);


#endif
