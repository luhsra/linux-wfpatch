#ifndef _AS_GENERATION_H
#define _AS_GENERATION_H

#include <linux/list.h>

struct mm_generation {
    struct mm_struct *mm;
    int id;
    struct list_head head;
};

void as_generation_exit(struct mm_struct *mm);

void membench_checkpoint(bool threshold);

#endif /* _AS_GENERATION_H */
