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
