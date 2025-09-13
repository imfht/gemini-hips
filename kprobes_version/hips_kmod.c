#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#define MODULE_NAME "hips_kmod"
#define MAX_BLACKLIST_ENTRIES 32
#define MAX_FILENAME_LEN 255

// The syscall function to probe. This can vary between architectures and kernel versions.
// __x64_sys_execve is common for x86_64.
#define SYSCALL_FUNC_NAME "__x64_sys_execve"

// --- Blacklist Storage ---
static char blacklist[MAX_BLACKLIST_ENTRIES][MAX_FILENAME_LEN];
static int blacklist_count = 0;
static DEFINE_SPINLOCK(blacklist_lock);

// --- /proc file implementation for blacklist management ---
static ssize_t proc_write_blacklist(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    char new_entry[MAX_FILENAME_LEN];
    unsigned long flags;

    if (count >= MAX_FILENAME_LEN) return -EINVAL;
    if (copy_from_user(new_entry, buffer, count)) return -EFAULT;

    if (count > 0 && new_entry[count - 1] == '\n') new_entry[count - 1] = '\0';
    else new_entry[count] = '\0';

    spin_lock_irqsave(&blacklist_lock, flags);
    if (blacklist_count < MAX_BLACKLIST_ENTRIES) {
        strncpy(blacklist[blacklist_count], new_entry, MAX_FILENAME_LEN - 1);
        blacklist[blacklist_count][MAX_FILENAME_LEN - 1] = '\0';
        blacklist_count++;
        pr_info("%s: Added '%s' to blacklist.\n", MODULE_NAME, new_entry);
    } else {
        pr_warn("%s: Blacklist is full.\n", MODULE_NAME);
    }
    spin_unlock_irqrestore(&blacklist_lock, flags);

    return count;
}

static const struct proc_ops proc_blacklist_ops = {
    .proc_write = proc_write_blacklist,
};

// --- Kprobe Handler ---
static int kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    char filename[MAX_FILENAME_LEN];
    const char __user *user_filename_ptr;
    const char *basename;
    int i;
    unsigned long flags;

    // On x86_64, the first argument of a syscall is in the DI register.
    user_filename_ptr = (const char __user *)regs->di;

    if (strncpy_from_user(filename, user_filename_ptr, sizeof(filename)) < 0) {
        return 0; // Cannot read filename, allow execution.
    }

    basename = strrchr(filename, '/');
    basename = basename ? basename + 1 : filename;

    spin_lock_irqsave(&blacklist_lock, flags);
    for (i = 0; i < blacklist_count; i++) {
        if (strcmp(basename, blacklist[i]) == 0) {
            spin_unlock_irqrestore(&blacklist_lock, flags);
            pr_warn("%s: BLOCKED execution of '%s' (PID: %d)\n", MODULE_NAME, filename, current->pid);
            
            // To block the syscall, we overwrite the return value register (AX)
            // with an error code and return 1 to prevent the original function from running.
            regs->ax = -EPERM;
            return 1;
        }
    }
    spin_unlock_irqrestore(&blacklist_lock, flags);

    return 0; // Allow execution
}

// --- Kprobe Registration ---
static struct kprobe kp = {
    .symbol_name = SYSCALL_FUNC_NAME,
    .pre_handler = kprobe_pre_handler,
};

// --- Module Init and Exit ---
static int __init hips_init(void) {
    int ret;
    proc_create("hips_blacklist", 0222, NULL, &proc_blacklist_ops);

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("%s: Failed to register kprobe for %s: %d\n", MODULE_NAME, SYSCALL_FUNC_NAME, ret);
        return ret;
    }

    pr_info("%s: HIPS Kernel Module Loaded (Kprobe on %s).\n", MODULE_NAME, SYSCALL_FUNC_NAME);
    return 0;
}

static void __exit hips_exit(void) {
    unregister_kprobe(&kp);
    remove_proc_entry("hips_blacklist", NULL);
    pr_info("%s: HIPS Kernel Module Unloaded.\n", MODULE_NAME);
}

module_init(hips_init);
module_exit(hips_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gemini");
MODULE_DESCRIPTION("A simple HIDS kernel module using kprobes.");