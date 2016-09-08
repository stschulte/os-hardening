#ifndef HARDEN_COLLECTOR_USER_H
#define HARDEN_COLLECTOR_USER_H

void validate_homefile(struct check* check, struct passwd* user, const char* filename, mode_t mask);
int collector_user_evaluate(struct report* report);

#endif
