#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>  //for system call number
#include <asm/io.h>  // page_to_virt, page_to_pfn
#include <linux/sched.h> // task_struct definition
#include <linux/fs.h> //struct file
#include <linux/proc_fs.h> /* create_proc_entry -> now is called "proc_create"*/
#include <asm/uaccess.h>  /* copy_from_user */
#include <asm/unistd.h>
#include <linux/types.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <linux/slab.h>

#include <linux/exception_monitor.h>

#include <asm/page.h>
#include <asm/page_types.h>

#include <asm/fpu/internal.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

#if defined(CONFIG_X86_INVLPG) || defined(CONFIG_X86_64)
# define cpu_has_invlpg         1
#else
# define cpu_has_invlpg         (boot_cpu_data.x86 > 3)
#endif

// CR4 reference: https://github.com/seporaitis/xv6-public/wiki/CPU-Registers-CR4
#define PKE_OFFSET 22
#define SMAP_OFFSET 21
#define SMEP_OFFSET 20
#define CR4_RESERVED_LOWEST 23

// CR0 reference: https://github.com/seporaitis/xv6-public/wiki/CPU-Registers-CR0
#define PG_OFFSET 31
#define CD_OFFSET 30
#define NW_OFFSET 29
#define WP_OFFSET 16
#define PE_OFFSET 0
#define TS_OFFSET 3
#define MP_OFFSET 1

#define CACHE_LEVEL_MEMORY 0
#define CACHE_LEVEL_L1 1
#define CACHE_LEVEL_L2 2
#define CACHE_LEVEL_L3 3

#define TLB_NOT_PRESENT 0
#define TLB_PRESENT 1

struct task_struct* task;
struct vm_area_struct* vma;

long mode;
size_t address;
size_t p_address; // also use this as the legal address
size_t va_page_address;
size_t flags;
int smap = 0;
int tlb_present = 1;
int cache_level = 1;
int expected_data = 0x42;

char *_mem = NULL;
char *mem = NULL;

uint64_t *_dummy_secret = NULL;
uint64_t *dummy_secret = NULL;

int monitor_victim_pages = 0;

// int __user* monitor_exception_buffer = NULL;

size_t cache_miss_threshold = 0;

unsigned char cheating_extable_buffer[256];

extern char msr_access_inst, msr_access_fix, msr_write_inst, msr_write_fix;

static inline void flush(void *p) {
  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

static inline void maccess(void *p) {
  asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");
}

static inline uint64_t my_rdtsc(void) {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

static inline void native_flush_tlb(void)
{ 
  native_write_cr3(native_read_cr3());
}

static inline void flush_tlb_single(unsigned long addr)
{
  asm volatile("invlpg (%0)" : : "r" (addr) : "memory");
}

static inline int flush_reload(void *ptr) {
  uint64_t start = 0, end = 0;

  start = my_rdtsc();
  maccess(ptr);
  end = my_rdtsc();

  flush(ptr);
  printk("ts = %llu\n", end - start);

  if (end - start < cache_miss_threshold) {
    return 1;
  }
  return 0;
}

static void detect_flush_reload_threshold(void) {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t dummy[16];
  size_t *ptr = dummy + 8;
  uint64_t start = 0, end = 0;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    start = my_rdtsc();
    maccess(ptr);
    end = my_rdtsc();
    reload_time += (end - start);
  }
  for (i = 0; i < count; i++) {
    start = my_rdtsc();
    maccess(ptr);
    end = my_rdtsc();
    flush(ptr);
    flush_reload_time += (end - start);
  }
  reload_time /= count;
  flush_reload_time /= count;

  printk("Flush+Reload: %zd cycles, Reload only: %zd cycles\n",
        flush_reload_time, reload_time);
  cache_miss_threshold = (flush_reload_time + reload_time * 2) / 3;
  printk("Flush+Reload threshold: %zd cycles\n",
        cache_miss_threshold);
}

static inline void my_wrmsr(uint64_t msr, uint64_t value)
{
  uint32_t low = value & 0xFFFFFFFF;
  uint32_t high = value >> 32;
  asm volatile (
    "wrmsr"
    :
    : "c"(msr), "a"(low), "d"(high)
  );
}

static inline uint64_t my_rdmsr(uint64_t msr)
{
  uint32_t low, high;
  asm volatile (
    "rdmsr"
    : "=a"(low), "=d"(high)
    : "c"(msr)
  );
  return ((uint64_t)high << 32) | low;
}

static inline void native_check_MP(void)
{
  printk("MP %lx\n", (native_read_cr0() >> MP_OFFSET) & 1UL);
}

static inline void native_MP_set(int enable)
{
  if (enable)
    native_write_cr0(native_read_cr0() | (1UL << MP_OFFSET));
  else
    native_write_cr0(native_read_cr0() & ~(1UL << MP_OFFSET));
}

static inline void fpu_lazy_switch_simulate(void)
{
  // Under development
}

static inline void native_check_TS(void)
{
  if ((native_read_cr0() >> TS_OFFSET) & 1UL)
  printk("TS set\n");
}

static inline void native_TS_set(int enable)
{
  if (enable)
    native_write_cr0(native_read_cr0() | (1UL << TS_OFFSET));
  else
    native_write_cr0(native_read_cr0() & ~(1UL << TS_OFFSET));
}

static inline void native_SMAP_set(int enable)
{
  if (enable)
    native_write_cr4(native_read_cr4() | (1UL << SMAP_OFFSET));
  else
    native_write_cr4(native_read_cr4() & ~(1UL << SMAP_OFFSET));
}

static inline void set_reserved(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = pte->pte | (1UL << 51); //set reserved bit
}

static inline void set_present(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = pte->pte ^ (1UL); //set/clear present bit
}

static inline void set_cacheable(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = pte->pte | (1UL << 4); //set/clear CD bit
}

static inline void set_rw(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = pte->pte ^ (1UL << 1); //set/clear rw bit
    printk("%lx pte: %lx", vaddr, pte->pte);
}

static inline void set_us(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = pte->pte ^ (1UL << 2); //set/clear us bit
    printk("%lx pte: %lx", vaddr, pte->pte);
}

static inline void set_xd(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = pte->pte ^ (1UL << 63); //set/clear xd bit
}

static inline void set_pkey(unsigned long vaddr, int pkey)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    // pkey is 4-bit long
    if (pkey > 0xf)
      pkey = 0;

    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return;
    }
    
    pte->pte = (pte->pte & (~(0xfUL << 59))) | ((unsigned long)pkey << 59);
}

static inline size_t translate(unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
 
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return 0;
    }
 
    pud = pud_offset(pgd, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return 0;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return 0;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return 0;
    }
    
    // printk("pte found as %lx\n", pte->pte);
    return ((pte->pte) & PHYSICAL_PAGE_MASK) | (vaddr & (PAGE_SIZE-1));
}

void prepare_data_condition(size_t legal_addr, int cache_level, int tlb_present) {
  // printk("legal_addr %lx", legal_addr);
  switch (cache_level) {
    case CACHE_LEVEL_L1:
      // printk("222\n");
      maccess((void *)legal_addr);
      break;
    case CACHE_LEVEL_MEMORY:
      // printk("111\n");
      flush((void *)legal_addr);
      break;
    case CACHE_LEVEL_L2:
    case CACHE_LEVEL_L3:
    default:
      // printf("Invalid cache level!\n");
      // return -1;
      break;
  }
  asm volatile("mfence");

  if (tlb_present == TLB_PRESENT) {
    // this should be done by user-space or just leave it default
  }
  else if (tlb_present == TLB_NOT_PRESENT) {;
    native_flush_tlb();
  }
}

int supervisor_mode_meltdown_test(size_t address)
{
  size_t retries = 1000;
  int count[3] = {0, 0, 0};
  int i;

  while (retries--) {
    native_SMAP_set(0);
    prepare_data_condition(p_address, cache_level, tlb_present);
    native_SMAP_set(smap);
    flush(mem - 64);
    // flush(mem + 0x42000);
    // flush(mem);

    // retpoline suppressing exception
    __asm__ volatile (
        "mov %1, %%r11\n\t"
        "mov %0, %%r10\n\t"
        "mfence\n\t"

        "call set_up_target\n\t"
        "movq (%%r11), %%r11\n\t"
        "movq (%%r10, %%r11, 1), %%r11\n\t"
        "capture: pause\n\t"
        "jmp capture\n\t"
        "set_up_target: lea 0xc(%%rip), %%r8\n\t"
        "movq %%r8, (%%rsp)\n\t"
        "clflush (%%rsp)\n\t"
        "mfence\n\t"
        "ret\n\t"
        "destination: nop\n\t"
        :
        : "r" (mem), "r" (address)
        : "r8", "%r10", "%r11"
      );

    // if (l1_evict_reload_print((void *)legal))
    //   count[2]++;

    i = expected_data;
    if (flush_reload(mem + i * 4096)) { // B
        count[0]++;
    }
    i = 0;
    if (flush_reload(mem + i * 4096)) { // 0
        count[1]++;
    }
  }
  // printf("secret in l1/l2 %d\n", count[2]);
  printk("0x%x - %d; 0x0 - %d\n", expected_data, count[0], count[1]);
  if (count[0] == 0 && count[1] == 0)
    return -1;
  else
    return (count[0] >= count[1]) ? expected_data : 0x0;
}

// int my_proc_write(struct file *file, const char __user *buffer, unsigned long count, void *data )
ssize_t my_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *data)
{
  char buf[80];
  char start[40];
  //printk("%s %lu", buffer, count);
  if (count < 1)
    return -EINVAL;  
  if (copy_from_user(buf, buffer, count)) {
    return -EFAULT;
  }

  buf[count] = '\0';
  // printk("Input: %s\n", buf);

  strcpy(start, buf);
  // printk("Start[1] = \'%c\', start[2] = \'%c\'\n", start[1], start[2]);
  if (start[1] == ' ' || start[1] == '\0') {
    start[1] = '\0'; // start is the first digit of input
    kstrtol(start, 16, &mode);
  } else if (start[2] == ' ' || start[2] == '\0') {
    start[2] = '\0';
    kstrtol(start, 16, &mode);
  } else {
    printk("Input: %s; mode unable to parse\n", buf);
    return 0;
  }

  task = current;
  switch(mode) {
    case 0:
      native_flush_tlb();
      // printk("[!]All TLB flushed.\n");
      break;
    case 1:
      kstrtoul(buf+2, 16, &address);
      // printk("SetExec %lx\n", address);
      // flush_tlb_single(address);
      // native_flush_tlb();
      set_victim(address, monitor_victim_pages);
      monitor_victim_pages ^= 1;
      set_xd(address);
      native_flush_tlb();
      break;
    case 2:
      kstrtoul(buf+2, 16, &address);
      // printk("Accessing %lx\n", address);
      // setexec(address);
      asm volatile("movq (%0), %%rax\n" : : "c"(address) : "rax");
      break;
    case 3:
      kstrtoul(buf+2, 16, &address);
      // printk("Set reserved bit %lx\n", address);
      set_victim(address, monitor_victim_pages);
      monitor_victim_pages ^= 1;
      set_reserved(address);
      // flush_tlb_single(address);
      native_flush_tlb();
      break;
    case 4:
      kstrtoul(buf+2, 16, &address);
      // printk("vaddr = %lx\n", address);
      size_t paddr = translate(address);
      // printk("paddr = %lx\n", paddr);
      return paddr;
      break;
    case 5:
      kstrtoul(buf+2, 16, &flags);
      smap = (int)(flags & 0x1);
      cache_level = (int)((flags >> 1) & 0x3);
      tlb_present = (int)((flags >> 3) & 0x3);
      printk("config address %lx, flags %d %d %d\n", address, smap, cache_level, tlb_present);
      // native_SMAP_set(0);
      // before calling #5, call #4 first so the address gets saved
      // prepare_data_condition(address, cache_level, tlb_present);
      // native_SMAP_set(smap);
      break;
    case 6:
      // p_address is used as pkey
      // address is the address
      // call #4 first to set address
      kstrtoul(buf+2, 16, &p_address);
      // printk("Set physical address %lx\n", address);
      set_pkey(address, (int)p_address);
      break;
    case 7:
      kstrtoul(buf+2, 16, &address);
      // printk("Set reserved bit %lx\n", address);
      set_present(address);
      // flush_tlb_single(address);
      native_flush_tlb();
      break;
    case 8:
      kstrtoul(buf+2, 16, &address);
      // printk("Set reserved bit %lx\n", address);
      set_rw(address);
      // flush_tlb_single(address);
      native_flush_tlb();
      break;
    case 9:
      kstrtoul(buf+2, 16, &address);
      // printk("Set reserved bit %lx\n", address);
      set_us(address);
      // flush_tlb_single(address);
      native_flush_tlb();
      break;
    case 0xa:
      printk("CR4 = 0x%lx\n", native_read_cr4());
      return (native_read_cr4() & 0xff);
      break;
    case 0xb:
      kstrtoul(buf+2, 16, &address);
      uint64_t value = my_rdmsr(address);
      printk("MSR = 0x%llx\n", value);
      return ((value & 0xff0000) >> 16);
      break;
    case 0xc:
      kstrtoul(buf+2, 16, &address);
      // printk("Set reserved bit %lx\n", address);
      set_cacheable(address);
      // flush_tlb_single(address);
      native_flush_tlb();
      break;
    case 0xd:
      kstrtoul(buf+2, 16, &address);
      // int ts = (int)(address & 0x1);
      int mp = (int)((address >> 1) & 0x1);
      // native_check_MP();
      // native_TS_set(ts);
      native_MP_set(mp);
      fpu_lazy_switch_simulate();
      native_check_TS();
      // printk("Set TS=%d, MP=%d\n", ts, mp);
      break;
    case 0xf:
      kstrtoul(buf+2, 16, &p_address); // this is the legal address
      return supervisor_mode_meltdown_test(address);
      break;
    default:
      printk("[!]Unknown instruction \"%s\".\n", buf);
      break;
  }
  return count;
}

int init_covert_buffer(void)
{
  int j;

  _mem = (char *)kmalloc(4096 * 300, GFP_KERNEL);
  if (!_mem) {
    printk("[!] Erro when allocating _mem\n");
    return -1;
  }

  for (j = 0; j < 128; j++) {
    uint64_t *temp = (uint64_t *)_mem + j;
    *temp = (uint64_t)(temp + 1);
  }

  mem = (char *)(((size_t)_mem & ~0xfff) + 0x1000 * 2);
  memset(mem, 0xab, 4096 * 290);

  // should set last cache line as "phys"
  for (j = 0; j < 64; j++) {
     uint64_t *temp = (uint64_t *)(mem + 64 * j);
     *temp = (uint64_t)(mem + 64 * (j+1));
  }

  for (j = 0; j < 256; j++) {
    flush(mem + j * 4096);
  }

  return 0;
}

int init_secret_buffer(void)
{
  int j;

  _dummy_secret = kmalloc(4096 * 3, GFP_KERNEL);
  if (!_dummy_secret) {
    printk("[!] Erro when allocating _dummy_secret\n");
    return -1;
  }

  for (j = 0; j < 3; j++) {
    uint64_t *temp = _dummy_secret + 0x1000/sizeof(uint64_t);
    *temp = 0x21;
  }

  dummy_secret = (uint64_t *)(((size_t)_dummy_secret & ~0xfff) + 0x1000);
  *dummy_secret = 0x42000;

  flush(dummy_secret);

  return 0;
}

int __init init_AddressConvert(void)
{
  struct proc_dir_entry *my_proc_file = NULL;
  
  static const struct file_operations my_proc_fops = {
    .owner = THIS_MODULE,
    .write = my_proc_write,
  };
  my_proc_file = proc_create("setexec", S_IRUSR |S_IWUSR | S_IRGRP | S_IROTH, NULL, &my_proc_fops); 
  if(my_proc_file == NULL)
    return -ENOMEM;

  mode = 0;
  init_covert_buffer();
  init_secret_buffer();
  detect_flush_reload_threshold();
  
  printk("SetExec Module Init.\n");
  return 0;
}

void __exit exit_AddressConvert(void)
{
  // kfree(monitor_exception_buffer);
  kfree(_dummy_secret);
  remove_proc_entry("setexec", NULL);
  kfree(_mem);
  printk("SetExec Module Exit.\n");
}

module_init(init_AddressConvert);
module_exit(exit_AddressConvert);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A kernel module to SetExec");
