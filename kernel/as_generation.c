#include <linux/printk.h>
#include <linux/syscalls.h>
#include <asm/current.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/as_generation.h>
#include <linux/vmacache.h>
#include <linux/sched/mm.h>
#include <asm/mmu_context.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/pid.h>

void as_generation_exit(struct mm_struct *mm) {
	down_write(&mm->master_mm->mmap_sem);

	// The master_mm must be freed last.
	WARN_ON(mm == mm->master_mm && !list_empty(&mm->generation_siblings));

	list_del(&mm->generation_siblings);

	up_write(&mm->master_mm->mmap_sem);
}

SYSCALL_DEFINE0(as_generation_create)
{
	struct task_struct *target, *group_leader;
	struct mm_struct *new_mm;
	struct mm_generation *new_generation;
	int id;

	printk(KERN_INFO "as_generation: create\n");

	target = current;
	group_leader = target->group_leader;

	// Duplicate mm
	new_mm = as_generation_dup_mm(target);
	// New mm already has mm_users == 1
	// So, we do not call mmget for the mm_generations list

	new_generation = kmalloc(sizeof(struct mm_generation), GFP_KERNEL);

	if (!has_mm_generations(group_leader)) {
		// Initialize mm_generations structure and first entry
		struct mm_generation *old_generation;

		old_generation = kmalloc(sizeof(struct mm_generation), GFP_KERNEL);
		old_generation->mm = target->mm;
		old_generation->id = 0;
		mmget(old_generation->mm); // mmget for the mm_generations list

		task_lock(group_leader);
		INIT_LIST_HEAD(&group_leader->mm_generations);
		list_add_tail(&old_generation->head, &group_leader->mm_generations);
	} else {
		task_lock(group_leader);
	}

	// Add new_mm to the generations list
	group_leader->max_generation_id++;
	id = group_leader->max_generation_id;
	new_generation->mm = new_mm;
	new_generation->id = id;
	list_add_tail(&new_generation->head, &group_leader->mm_generations);
	task_unlock(group_leader);

	// The mm has already been added to the siblings list.
	// Its master_mm is also set.
	// This happened in as_generation_dup_mmap with the mmap_sem write-locked.

	printk(KERN_INFO "as_generation: created: %d\n", id);

	return id;
}

SYSCALL_DEFINE1(as_generation_migrate, int, id)
{
	struct task_struct *target, *group_leader;
	struct mm_struct *old_mm;
	struct mm_generation *generation = NULL;
	int old_id;
	int ret = 0;

	target = current;
	group_leader = target->group_leader;
	old_id = target->current_generation_id;

	printk(KERN_INFO "as_generation: migrate - pid: %d, thread: %d, from: %d to: %d\n",
	       group_leader->pid, target->pid, old_id, id);

	task_lock(group_leader);

	// Address space generations is not initialized
	if (group_leader->max_generation_id == 0) {
		ret = -EPERM;
		goto fail;
	}

	// Find generation with id
	list_for_each_entry(generation, &group_leader->mm_generations, head) {
		if (generation->id == id)
			break;
	}
	if (!generation || generation->id != id) {
		ret = -EINVAL;
		goto fail;
	}

	if (target != group_leader)
		task_lock(target);

	// Exchange mms
	old_mm = target->active_mm;
	target->mm = generation->mm;
	target->active_mm = generation->mm;
	target->current_generation_id = id;
	vmacache_flush(target);
	sync_mm_rss(old_mm);
	mmget(generation->mm);

	if (target != group_leader)
		task_unlock(target);

	task_unlock(group_leader);

	activate_mm(old_mm, target->active_mm);
	mmput(old_mm);

	printk(KERN_INFO "as_generation: thread: %d: migration successful\n", target->pid);

	return old_id;
fail:
	task_unlock(group_leader);
	return ret;
}


/* Similar vma split as in __do_munmap */
SYSCALL_DEFINE2(as_generation_pin, unsigned long, addr, unsigned long, len)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev, *last, *tmp;
	unsigned long end;
	int ret = 0;

	down_write(&mm->master_mm->mmap_sem);

	/* Pin is only allowed before any generations have been created. */
	if (has_as_generations(mm)) {
		ret = -EPERM;
		goto out;
	}

	if ((offset_in_page(addr)) || addr > TASK_SIZE || len > TASK_SIZE-addr) {
		ret = -EINVAL;
		goto out;
	}

	len = PAGE_ALIGN(len);
	if (len == 0) {
		ret = -EINVAL;
		goto out;
	}

	vma = find_vma(mm, addr);
	if (!vma) {
		ret = -EINVAL;
		goto out;
	}
	prev = vma->vm_prev;

	end = addr + len;
	if (vma->vm_start >= end) {
		ret = -EINVAL;
		goto out;
	}

	/* Split beginning VMA */
	if (addr > vma->vm_start) {
		if (mm->map_count >= sysctl_max_map_count) {
			ret = -ENOMEM;
			goto out;
		}

		ret = __split_vma(mm, vma, addr, 0);
		if (ret)
			goto out;
		prev = vma;
	}

	/* Split ending VMA */
	last = find_vma(mm, end);
	if (last && end > last->vm_start) {
		ret = __split_vma(mm, last, end, 1);
		if (ret)
			goto out;
	}
	vma = prev ? prev->vm_next : mm->mmap;

	/* Make some checks */
	tmp = vma;
	while (tmp && tmp->vm_start < end) {
		if (is_vm_hugetlb_page(tmp))
			BUG();
		if ((tmp->vm_flags & VM_SHARED) && !tmp->as_generation_shared) {
			ret = -EACCES;
			goto out;
		}
		tmp = tmp->vm_next;
	}

	/* Finally set as_generation_shared flag */
	tmp = vma;
	while (tmp && tmp->vm_start < end) {
		tmp->as_generation_shared = false;
		tmp = tmp->vm_next;
	}
out:
	up_write(&mm->master_mm->mmap_sem);
	return ret;
}


SYSCALL_DEFINE1(as_generation_delete, int, id)
{
	struct task_struct *group_leader;
	struct mm_generation *generation = NULL;

	printk(KERN_INFO "as_generation: delete: %d\n", id);

	if (id == 0)
		return -EPERM;

	group_leader = current->group_leader;

	task_lock(group_leader);

	// Find the referenced generation
	list_for_each_entry(generation, &group_leader->mm_generations, head) {
		if (generation->id == id)
			break;
	}
	if (!generation || generation->id != id) // none was found
		goto fail;

	// We do not check if a task still has this mm set.
	// So it could happen, that a task still uses the to-be-removed generation.
	// This is fine as the mm stays in the siblings list until its freeing.
	// It cannot, however, be newly switched to by some other task.
	list_del(&generation->head);

	task_unlock(group_leader);

	mmput(generation->mm);
	kfree(generation);

	return 0;

fail:
	task_unlock(group_leader);
	return -EINVAL;
}


#if !defined(__PAGETABLE_P4D_FOLDED) || defined(__PAGETABLE_PUD_FOLDED) || defined(__PAGETABLE_PMD_FOLDED)
#   error "Unexpected page table folding."
#endif

#if CONFIG_PGTABLE_LEVELS != 4
#   error "Unexpected page table level."
#endif

static void pte_account(pte_t *ptep, size_t n, unsigned long *acc)
{
	size_t i;

	for (i = 0; i < n; ++i) {
		if (pte_present(ptep[i])) {
			/* printk(KERN_INFO "                pte entry: %lu\n", i); */
			acc[4]++;
		}
	}
}

static void pmd_account(pmd_t *pmdp, size_t n, struct mm_struct *mm, unsigned long *acc)
{
	size_t i;
	/* spinlock_t *ptl; */

	for (i = 0; i < n; ++i) {
		if (pmd_present(pmdp[i])) {
			if (WARN_ON(pmd_huge(pmdp[i]))) {
			} else {
				/* printk(KERN_INFO "            pmd entry: %lu\n", i); */
				acc[3]++;
				/* ptl = pte_lockptr(mm, &pmdp[i]); */
				/* spin_lock(ptl); */
				pte_account((pte_t *)pmd_page_vaddr(pmdp[i]), PTRS_PER_PTE, acc);
				/* spin_unlock(ptl); */
			}
		}
	}
}

static void pud_account(pud_t *pudp, size_t n, struct mm_struct *mm, unsigned long *acc)
{
#ifdef __PAGETABLE_PMD_FOLDED
	pmd_account((pmd_t *)pudp, n, mm);
#else
	size_t i;

	for (i = 0; i < n; ++i) {
		if (pud_present(pudp[i])) {
			if (WARN_ON(pud_huge(pudp[i]))) {
			} else {
				/* printk(KERN_INFO "        pud entry: %lu\n", i); */
				acc[2]++;
				pmd_account((pmd_t *)pud_page_vaddr(pudp[i]), PTRS_PER_PMD, mm, acc);
			}
		}
	}
#endif
}

static void p4d_account(p4d_t *p4dp, size_t n, struct mm_struct *mm, unsigned long *acc)
{
#ifdef __PAGETABLE_PUD_FOLDED
	pud_account((pud_t *)p4dp, n, mm, acc);
#else
	size_t i;
	for (i = 0; i < n; ++i) {
		if (p4d_present(p4dp[i])) {
			/* printk(KERN_INFO "    p4d entry: %lu\n", i); */
			acc[1]++;
			pud_account((pud_t *)p4d_page_vaddr(p4dp[i]), PTRS_PER_PUD, mm, acc);
		}
	}
#endif
}

static void pgd_account(pgd_t *pgdp, size_t n, struct mm_struct *mm, unsigned long *acc)
{
#ifdef __PAGETABLE_P4D_FOLDED
	p4d_account((p4d_t*)pgdp, n, mm, acc);
#else
	size_t i;
	for (i = 0; i < n; ++i) {
		if (pgd_present(pgdp[i])) {
			/* printk(KERN_INFO "pgd entry: %lu\n", i); */
			acc[0]++;
			p4d_account((p4d_t*)pgd_page_vaddr(pgdp[i]), PTRS_PER_P4D, mm, acc);
		}
	}
#endif
}

static struct kobject *membench_generations;
static DEFINE_SPINLOCK(membench_lock);
static pid_t membench_pid;
static ktime_t membench_then = 0;
static unsigned long max_master_entries[5];
static unsigned long max_master_total;
static unsigned long max_sibling_entries[5];
static unsigned long max_sibling_total;
static unsigned long max_generations;
static unsigned long last_master_entries[5];
static unsigned long last_master_total;
static unsigned long last_sibling_entries[5];
static unsigned long last_sibling_total;
static unsigned long last_generations;

static void do_membench_checkpoint(struct mm_struct *master_mm) {
	struct mm_struct *mm_cursor;
	unsigned long master_entries[5];
	unsigned long master_total;
	unsigned long sibling_entries[5];
	unsigned long sibling_total;
	unsigned long generations;

	printk(KERN_INFO "membench: measurement");

	master_entries[0] = 0;
	master_entries[1] = 0;
	master_entries[2] = 0;
	master_entries[3] = 0;
	master_entries[4] = 0;

	sibling_entries[0] = 0;
	sibling_entries[1] = 0;
	sibling_entries[2] = 0;
	sibling_entries[3] = 0;
	sibling_entries[4] = 0;

	pgd_account(master_mm->pgd, KERNEL_PGD_BOUNDARY, master_mm, master_entries);
	master_total = master_entries[0] + master_entries[1] + master_entries[2] + master_entries[3];

	generations = 0;
	list_for_each_entry(mm_cursor,
			    &master_mm->generation_siblings,
			    generation_siblings) {
		pgd_account(mm_cursor->pgd, KERNEL_PGD_BOUNDARY, mm_cursor, sibling_entries);
		generations++;
	}
	if (generations > 0) {
		sibling_entries[0] /= generations;
		sibling_entries[1] /= generations;
		sibling_entries[2] /= generations;
		sibling_entries[3] /= generations;
		sibling_entries[4] /= generations;
		sibling_total = sibling_entries[0] + sibling_entries[1] + sibling_entries[2] + sibling_entries[3];
	} else {
		sibling_entries[0] = 0;
		sibling_entries[1] = 0;
		sibling_entries[2] = 0;
		sibling_entries[3] = 0;
		sibling_entries[4] = 0;
		sibling_total = 0;
	}
	generations++; // Master

	if (master_total > max_master_total) {
		max_master_entries[0] = master_entries[0];
		max_master_entries[1] = master_entries[1];
		max_master_entries[2] = master_entries[2];
		max_master_entries[3] = master_entries[3];
		max_master_entries[4] = master_entries[4];
		max_master_total = master_total;
		max_sibling_entries[0] = sibling_entries[0];
		max_sibling_entries[1] = sibling_entries[1];
		max_sibling_entries[2] = sibling_entries[2];
		max_sibling_entries[3] = sibling_entries[3];
		max_sibling_entries[4] = sibling_entries[4];
		max_sibling_total = sibling_total;
		max_generations = generations;
	}

	last_master_entries[0] = master_entries[0];
	last_master_entries[1] = master_entries[1];
	last_master_entries[2] = master_entries[2];
	last_master_entries[3] = master_entries[3];
	last_master_entries[4] = master_entries[4];
	last_master_total = master_total;
	last_sibling_entries[0] = sibling_entries[0];
	last_sibling_entries[1] = sibling_entries[1];
	last_sibling_entries[2] = sibling_entries[2];
	last_sibling_entries[3] = sibling_entries[3];
	last_sibling_entries[4] = sibling_entries[4];
	last_sibling_total = sibling_total;
	last_generations = generations;
}

void membench_checkpoint(bool threshold) {
	unsigned long flags;
	struct task_struct *task = current;
	ktime_t now;
	pid_t pid = task_pid_nr(task);

	// mm_sem is taken

	if (pid != membench_pid)
		return;

	if (!spin_trylock_irqsave(&membench_lock, flags))
		return;

	now = ktime_get();
	if (threshold && (membench_then + ms_to_ktime(50) > now))
		goto unlock;
	membench_then = now;

	if (pid != membench_pid)
		goto unlock;

	do_membench_checkpoint(task->mm->master_mm);

unlock:
	spin_unlock_irqrestore(&membench_lock, flags);
}

static ssize_t membench_pid_show(struct kobject *kobj, struct kobj_attribute *attr,
				 char *buf)
{
	unsigned long flags;
	ssize_t len;

	spin_lock_irqsave(&membench_lock, flags);
        len = sprintf(buf, "%d\n", membench_pid);
	spin_unlock_irqrestore(&membench_lock, flags);
	return len;
}

static ssize_t membench_pid_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	unsigned long flags;
	spin_lock_irqsave(&membench_lock, flags);
	max_generations = 0;
	max_master_total = 0;
	max_master_entries[0] = 0;
	max_master_entries[1] = 0;
	max_master_entries[2] = 0;
	max_master_entries[3] = 0;
	max_master_entries[4] = 0;
	max_sibling_total = 0;
	max_sibling_entries[0] = 0;
	max_sibling_entries[1] = 0;
	max_sibling_entries[2] = 0;
	max_sibling_entries[3] = 0;
	max_sibling_entries[4] = 0;
	last_master_total = 0;
	last_master_entries[0] = 0;
	last_master_entries[1] = 0;
	last_master_entries[2] = 0;
	last_master_entries[3] = 0;
	last_master_entries[4] = 0;
	last_sibling_total = 0;
	last_sibling_entries[0] = 0;
	last_sibling_entries[1] = 0;
	last_sibling_entries[2] = 0;
	last_sibling_entries[3] = 0;
	last_sibling_entries[4] = 0;
        sscanf(buf, "%d", &membench_pid);
	spin_unlock_irqrestore(&membench_lock, flags);
        return count;
}

static ssize_t membench_dump_show(struct kobject *kobj, struct kobj_attribute *attr,
				  char *buf)
{
	unsigned long flags;
	ssize_t len;

	struct pid *pid_struct = find_get_pid(membench_pid);
	struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);

	spin_lock_irqsave(&membench_lock, flags);

	if (task)
		do_membench_checkpoint(task->mm->master_mm);
	else
		printk(KERN_INFO "membench: process %d does not exist anymore.", membench_pid);

        len = sprintf(buf, "pid: %d\n"
		      "\nCURR:\ngenerations: %lu\n"
		      "master:          %lu (entries: pgd: %lu [0->folded], p4d: %lu, pud: %lu, pmd: %lu) + %lu ptes\n"
		      "siblings (avg):  %lu (entries: pgd: %lu [0->folded], p4d: %lu, pud: %lu, pmd: %lu) + %lu ptes\n"
		      "\nMAX:\ngenerations: %lu\n"
		      "master:          %lu (entries: pgd: %lu [0->folded], p4d: %lu, pud: %lu, pmd: %lu) + %lu ptes\n"
		      "siblings (avg):  %lu (entries: pgd: %lu [0->folded], p4d: %lu, pud: %lu, pmd: %lu) + %lu ptes\n",
		      membench_pid,
		      last_generations,
		      last_master_total,
		      last_master_entries[0], last_master_entries[1], last_master_entries[2], last_master_entries[3],
		      last_master_entries[4],
		      last_sibling_total,
		      last_sibling_entries[0], last_sibling_entries[1], last_sibling_entries[2], last_sibling_entries[3],
		      last_sibling_entries[4],
		      max_generations,
		      max_master_total,
		      max_master_entries[0], max_master_entries[1], max_master_entries[2], max_master_entries[3],
		      max_master_entries[4],
		      max_sibling_total,
		      max_sibling_entries[0], max_sibling_entries[1], max_sibling_entries[2], max_sibling_entries[3],
		      max_sibling_entries[4]);

	spin_unlock_irqrestore(&membench_lock, flags);

	return len;
}

static struct kobj_attribute membench_pid_attr = __ATTR(pid, 0660, membench_pid_show, membench_pid_store);
static struct kobj_attribute membench_dump_attr = __ATTR(dump, 0660, membench_dump_show, NULL);

static void __init setup_membench_generations(void) {
	int error = 0;

        membench_generations = kobject_create_and_add("as_generations", kernel_kobj);
        BUG_ON(!membench_generations);

        error = sysfs_create_file(membench_generations, &membench_pid_attr.attr);
        WARN_ON(error);
	error = sysfs_create_file(membench_generations, &membench_dump_attr.attr);
        WARN_ON(error);
}
__initcall(setup_membench_generations);
