virtual patch
virtual context
virtual org
virtual report

@@
expression mm;
@@

- mm->mmap_sem
+ mm->master_mm->mmap_sem
