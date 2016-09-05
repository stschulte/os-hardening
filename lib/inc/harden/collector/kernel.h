#ifndef HARDEN_COLLECTOR_KERNEL_H
#define HARDEN_COLLECTOR_KERNEL_H

void collector_check_verify_kernel_value(struct check*, const char* key, const char* expected_value);
int collector_kernel_evaluate(struct report* report);

#endif
