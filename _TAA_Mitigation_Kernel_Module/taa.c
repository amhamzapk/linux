
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/semaphore.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/segment.h>

#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include <linux/sched/signal.h>

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/profile.h>
#include <linux/notifier.h>

#include <linux/fs.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>


#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <stdarg.h>
#include <uapi/linux/string.h>
#include <asm/string.h>
#include <linux/cpu.h>
static int cpu = 0;
module_param(cpu, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(cpu, "CPU");

MODULE_LICENSE("GPL");              ///< The license type -- this affects runtime behavior
MODULE_AUTHOR("Ameer Hamza");      ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Xen Hello Module");  ///< The description -- see modinfo
MODULE_VERSION("0.1");              ///< The version of the module

/*
 * MACROS Definition
 */
long long buf_diff[1024] = {0};
#define NUM_SETS  		 	   64
#define LINE_SIZE 		       64
#define NUM_WAYS  		 	   8
#define INTERVAL_FLUSH_ONLY  	125000
#define INTERVAL_FLUSH_RELOAD  	5000

#define ATTACKS_DETECT	 5
#define NO_ISSUE		 0
#define FLUSH_ONLY		 1
#define TAA_ATTACK		 2
#define CPU_EXHAUST		 3
#define FLUSH_RELOAD	 4

/*
 * Functions
 */
void mfence_defence(void);
void cpuid_defence(void);
void maccess_defence(void *p);
void flush_defence(void *p);
void mfence_defence() { asm volatile("mfence"); }
void cpuid_defence() { asm volatile("cpuid"); }
void maccess_defence(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }
void flush_defence(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }

static __inline__ unsigned long long getticks(void)
{
     unsigned a, d;
     asm("cpuid");
     asm volatile("rdtsc" : "=a" (a), "=d" (d));

     return (((unsigned long long)a) | (((unsigned long long)d) << 32));
}

/*
 * Variables
 */

//#define ONLY_TEST

#ifndef ONLY_TEST
#define NUM_CPUS 8
#else
#define NUM_CPUS 1
#endif

char mapping_cache_line_set [8][NUM_WAYS * 4096] __attribute__((aligned(NUM_SETS*LINE_SIZE)));
static struct task_struct *thread_st_c_model_worker[NUM_CPUS];
bool is_bind_upper_half = 1;
static DEFINE_MUTEX(lock0);
static DEFINE_MUTEX(lock1);
static DEFINE_MUTEX(lock2);
static DEFINE_MUTEX(lock3);
volatile int first[NUM_CPUS] = {0};
volatile int wait_flag[4] = {0};
int happen[NUM_CPUS] = {0};
int min_diff = 10000000;
int min_per = 10000000;
int max_per = 0;
int cnter = 0;
int false_negative = 0;
int false_detect = 0;
int last_detect = -1;
int new_detect = -1;
int less_pid = 0;
volatile int false_negative_helper = 0;
#define MITIGATION2


unsigned int temp;
unsigned long temp1;
unsigned long temp2;
unsigned long temp3;
unsigned long temp4;
struct  page *page;
char    *myaddr;
unsigned int *myaddr_long;
int     res;
struct task_struct *last_curr;


unsigned long aligned_user_addr;
int offs;
unsigned long user_addr;


unsigned int b1 = 0;
unsigned int b2 = 0;
unsigned int b3 = 0;
unsigned int b4 = 0;
unsigned int last_b = 0;

static int c_model_worker_thread(void *unused) {
    int i, j, set=0;
    int max;
    int avrg;
    int min;
	int max2;
	int idx;
	int idx2;
	int idx_min;
	unsigned long long abrt_per;
	int diff;
	volatile long long detection_interval = 0;
	volatile long long no_abort_total = 0;
	volatile long long abort_total = 0;
	volatile long long abort_l1_total = 0;
	volatile long long abort_l1_set[NUM_SETS] = {0};
	volatile int	   detection_cnter[ATTACKS_DETECT] = {0};
	volatile unsigned long long tick_1=0, tick_diff=0;
	unsigned long long internal_cnter = 0;
	unsigned long long flush_only = 0;
	const int this_cpu = (const int) get_cpu();
	int this_cpu_lower = 0;
	char *mem_ptr;
	struct task_struct *task_list;
	volatile int detected_cpu = (get_cpu() < 4) ? (get_cpu() + 4) : get_cpu() - 4;

	mem_ptr = mapping_cache_line_set[this_cpu];

	for (j=0; j<NUM_WAYS; j++) {
	  memset(mapping_cache_line_set[this_cpu] + (j*4096), 0, 4096);
	}

    /* Run until module is not unloaded */
    while (!kthread_should_stop()) {

    	this_cpu_lower = (this_cpu < 4) ? this_cpu : (this_cpu-4);
    	if (first[this_cpu] == 0) {
    		first[this_cpu] = 1;
			while (wait_flag[this_cpu_lower] == 1) {
				msleep(10);
			}
			wait_flag[this_cpu_lower] = 1;
    	}

		for (set=0; set<NUM_SETS; set++) {
			volatile int abort_reason_local = 0;
			volatile int abort_local = 0;
			volatile int no_abort_local = 0;

			if (detection_interval < INTERVAL_FLUSH_RELOAD) {
				tick_1 = getticks();

				// This allows time stamp to be stabilized
				for (j=0; j<NUM_WAYS; j++) {
					mfence_defence();
				}
				flush_only = 700;
			} else {
				flush_only = 4;
			}

			__asm__ __volatile__ (
				"xbegin 2f;"         /* Begin TSX */

					"movq %11, %%rcx;"
					"L1:;"
					"movq (%3),  %%rax;" /* Access Way-1 */
					"movq (%4),  %%rax;" /* Access Way-2 */
					"movq (%5),  %%rax;" /* Access Way-3 */
					"movq (%6),  %%rax;" /* Access Way-4 */
					"movq (%7),  %%rax;" /* Access Way-5 */
					"movq (%8),  %%rax;" /* Access Way-6 */
					"movq (%9),  %%rax;" /* Access Way-7 */
					"movq (%10), %%rax;" /* Access Way-8 */
					"loop L1;"

				"xend;"				 /* End TSX */
				"movq %1, %%rcx;"    /* No Abort */
				"incq %%rcx;"		 /* Increment no_abort */
				"movq %%rcx, %1;"
				"jmp 3f;"			 /* Attack not mounted, exit */
				"2:;"				 /* Abort */
				"mov %%eax, %0;"	 /* Copy abort reason value from eax */
				"movq %2, %%rdx;"
				"incq %%rdx;"		 /* Increment total Abort */
				"movq %%rdx, %2;"
				"3:;"
				: "=g" (abort_reason_local), "=g"(no_abort_local), "=g"(abort_local) : "r" (mem_ptr + (set*64)),"r" (mem_ptr + (4096*1) + (set*64)),"r" (mem_ptr + (4096*2) + (set*64)),"r" (mem_ptr + (4096*3) + (set*64)),"r" (mem_ptr + (4096*4) + (set*64)),"r" (mem_ptr + (4096*5) + (set*64)),"r" (mem_ptr + (4096*6) + (set*64)),"r" (mem_ptr + (4096*7) + (set*64)), "g"(flush_only), "r"(abort_local), "r"(no_abort_local) : "rcx", "rdx", "rdi", "rax"
			);


			if (detection_interval < INTERVAL_FLUSH_RELOAD) {
				tick_diff += getticks() - tick_1;
				mfence_defence();
			} else {
				if (abort_reason_local & (1<<2)) {
					/* Increment abort counter */
					abort_l1_set[set]++;
					abort_l1_total++;
				}

				no_abort_total += no_abort_local;
				abort_total += abort_local;
				abort_local = no_abort_local = 0;
			}
		}

		/* To let other processes run */
		schedule_timeout (2000);

		if (++detection_interval > INTERVAL_FLUSH_ONLY) {
			mfence_defence();
			detection_interval = 0;
			max = 0;
			max2 = 0;
			idx = 0;
			idx2 = 0;
			idx_min = 0;
			avrg = 0;
			min = 0x0FFFFFFF;
			for (i=0; i<64; i++) {
				avrg += abort_l1_set[i];
				if (abort_l1_set[i] > max) {
					max2 = max;
					max = abort_l1_set[i];
					idx = i;
				}
				if (abort_l1_set[i] < min) {
					min = abort_l1_set[i];
					idx_min = i;
				}
				else if (abort_l1_set[i] > max2) {
					max2 = abort_l1_set[i];
					idx2 = i;
				}
				abort_l1_set[i] = 0;
			}
			avrg /= 64;

			abrt_per = ((abort_l1_total * 50000) / ((no_abort_total > 0) ? no_abort_total : 1));
			diff = max - max2;
			if ((diff < min_diff) && (this_cpu == 4)) {
				min_diff = diff;
			}
			if ((abrt_per < min_per) && (this_cpu == 4)) {
				min_per = abrt_per;
			}
			if ((abrt_per > max_per) && (this_cpu == 4)) {
				max_per = abrt_per;
			}


			if (detected_cpu == 1) {
				printk(KERN_INFO "TAA Attack Detected on CPU:[%d]\n", detected_cpu);
				printk(KERN_INFO "[Cnter=%d]\tPER=%lld\tTicks=%lld\tMax=%d\tMin=%d\tAvrg=%d\n", detection_cnter[TAA_ATTACK]++, abrt_per, tick_diff/INTERVAL_FLUSH_RELOAD, max, min, avrg);
			}

#ifndef ONLY_TEST
			if ((abrt_per > 60) &&
				((tick_diff/INTERVAL_FLUSH_RELOAD) > 500000) &&
				(max > 175) &&
				(min > 75) &&
				(avrg > 125))
#endif
			{
				last_detect = new_detect;
				new_detect = detected_cpu;
				happen[detected_cpu] = 1;
				if (detected_cpu == 1) {
					printk(KERN_ALERT "TAA Attack Detected on CPU:[%d]\n", detected_cpu);
					printk(KERN_ALERT "[Cnter=%d]\tPER=%lld\tTicks=%lld\tMax=%d\tMin=%d\tAvrg=%d\n", detection_cnter[TAA_ATTACK]++, abrt_per, tick_diff/INTERVAL_FLUSH_RELOAD, max, min, avrg);
				}

#ifndef ONLY_TEST
				false_negative_helper = 0;
				for_each_process(task_list) {
					i++;
					if (task_list->state == TASK_RUNNING && (task_list->cpu == detected_cpu)) {
//						 printk( KERN_ALERT "Killed Vulnerable Process with PID:[%d]\n",
//								 task_list->pid/*,
//								 task_list->cpu*/);

						/* To let other processes run */
						schedule_timeout (1000);

						if (!(task_list->state == TASK_RUNNING && (task_list->cpu == detected_cpu)))
							continue;

						schedule_timeout (1000);

						if (!(task_list->state == TASK_RUNNING && (task_list->cpu == detected_cpu)))
							continue;

						schedule_timeout (1000);

						if (!(task_list->state == TASK_RUNNING && (task_list->cpu == detected_cpu)))
							continue;


						if (task_list->pid < 1000) {
							less_pid++;
							continue;
						}

#ifdef MITIGATION2
//						 if (res) {
//							 printk(KERN_INFO "Got mmaped.\n");
//							 myaddr = kmap(page);
//							 printk(KERN_INFO "%s\n", myaddr);
//							 strcpy(myaddr, "Mohan");
//							 page_cache_release(page);
//						 }




//						__copy_from_user((unsigned char*)myaddr, (unsigned char*) task_list->mm->start_code, 1);
//						printk(KERN_ALERT "0x%llx\n", *(myaddr_long));
//						__copy_from_user()


						printk("START: 0x%lx\n", task_list->mm->start_code);
						printk("END: 0x%lx\n", task_list->mm->end_code);
						printk("Diff: %lx & %ld\n", task_list->mm->end_code - task_list->mm->start_code, task_list->mm->end_code - task_list->mm->start_code);





						 up_read(&task_list->mm->mmap_sem);
						 res = get_user_pages_remote(task_list, task_list->mm,
											  (unsigned long)task_list->mm->start_code,
											  1,
											  FOLL_WRITE | FOLL_FORCE, &page,
											  NULL, NULL);
						 down_read(&task_list->mm->mmap_sem);
						 if (res) {

							 printk(KERN_ALERT "IDLE START\n");

							 task_lock(task_list);
							 send_sig(SIGSTOP, task_list, 0);
//							 kill_pid(task_pid(task_list), SIGSTOP, 1);
							 task_unlock(task_list);
////							 set_task_state(task_list, TASK_IDLE);
//							 schedule();

							 myaddr_long = kmap(page);
							 for (i=0; i<4096/4; i++) {

//								 b8 = ((myaddr_long[i]) >> 56) & 0xff;
//								 b7 = ((myaddr_long[i]) >> 48) & 0xff;
//								 b6 = ((myaddr_long[i]) >> 40) & 0xff;
//								 b5 = ((myaddr_long[i]) >> 32) & 0xff;
								 b4 = ((myaddr_long[i]) >> 24) & 0xff;
								 b3 = ((myaddr_long[i]) >> 16) & 0xff;
								 b2 = ((myaddr_long[i]) >> 8) & 0xff;
								 b1 = ((myaddr_long[i])) & 0xff;
#if 1


								 if (b1 == 0xc7 && b2 == 0xf8) {
//									 printk(KERN_ALERT "\n\nGOT XBEGIN\n\n");


//									 printk(KERN_ALERT "BEFORE:\n");
//									 printk(KERN_ALERT "%02x %02x %02x %02x\n", b1, b2, b3, b4);
									 temp = myaddr_long[i];
									 temp &= ~(0xffffffff);
									 temp |= 0x90909090;
									 *(myaddr_long+i) = temp;

									 temp = myaddr_long[i+1];
									 temp &= ~(0x0000ffff);
									 temp |= 0x00009090;
									 *(myaddr_long+i+1) = temp;


//									 printk(KERN_ALERT "AFTER:\n");
									 b4 = ((myaddr_long[i]) >> 24) & 0xff;
									 b3 = ((myaddr_long[i]) >> 16) & 0xff;
									 b2 = ((myaddr_long[i]) >> 8) & 0xff;
									 b1 = ((myaddr_long[i])) & 0xff;
								 }









								 if (b2 == 0xc7 && b3 == 0xf8) {
//									 printk(KERN_ALERT "\n\nGOT XBEGIN\n\n");


//									 printk(KERN_ALERT "BEFORE:\n");
//									 printk(KERN_ALERT "%02x %02x %02x %02x\n", b1, b2, b3, b4);
									 temp = myaddr_long[i];
									 temp &= ~(0xffffff00);
									 temp |= 0x90909000;
									 *(myaddr_long+i) = temp;


									 temp = myaddr_long[i+1];
									 temp &= ~(0x00ffffff);
									 temp |= 0x00909090;
									 *(myaddr_long+i+1) = temp;


//									 printk(KERN_ALERT "AFTER:\n");
									 b4 = ((myaddr_long[i]) >> 24) & 0xff;
									 b3 = ((myaddr_long[i]) >> 16) & 0xff;
									 b2 = ((myaddr_long[i]) >> 8) & 0xff;
									 b1 = ((myaddr_long[i])) & 0xff;
								 }

								 if (last_b == 0xf && b1 == 0x1 && b2 == 0xd5) {

//									 printk(KERN_ALERT "\n\nGOT XEND\n\n");
//									 printk(KERN_ALERT "BEFORE:\n");
//									 printk(KERN_ALERT "%02x %02x %02x %02x\n", b1, b2, b3, b4);
									 temp = myaddr_long[i-1];
									 temp &= ~(0xff000000);
									 temp |= 0x90000000;
									 myaddr_long[i-1] = temp;

									 temp = myaddr_long[i];
									 temp &= ~(0x0000ffff);
									 temp |= 0x00009090;
									 myaddr_long[i] = temp;

//									 printk(KERN_ALERT "AFTER:\n");
									 b4 = ((myaddr_long[i]) >> 24) & 0xff;
									 b3 = ((myaddr_long[i]) >> 16) & 0xff;
									 b2 = ((myaddr_long[i]) >> 8) & 0xff;
									 b1 = ((myaddr_long[i])) & 0xff;
								 }


								 if (b1 == 0xf && b2 == 0x1 && b3 == 0xd5) {
//									 printk(KERN_ALERT "\n\nGOT XEND\n\n");


//									 printk(KERN_ALERT "BEFORE:\n");
//									 printk(KERN_ALERT "%02x %02x %02x %02x\n", b1, b2, b3, b4);
									 temp = myaddr_long[i];
									 temp &= ~(0x00ffffff);
									 temp |= 0x00909090;
									 myaddr_long[i] = temp;

//									 printk(KERN_ALERT "AFTER:\n");
									 b4 = ((myaddr_long[i]) >> 24) & 0xff;
									 b3 = ((myaddr_long[i]) >> 16) & 0xff;
									 b2 = ((myaddr_long[i]) >> 8) & 0xff;
									 b1 = ((myaddr_long[i])) & 0xff;
								 }
#endif
//								 *(myaddr_long+i) = 0;


//								 printk(KERN_ALERT "%02x %02x %02x %02x %02x %02x %02x %02x\n", b1, b2, b3, b4, b5, b6, b7, b8);
//								 printk(KERN_ALERT "%02x %02x %02x %02x\n", b1, b2, b3, b4);
								 last_b = b4;
							 }
//							 set_page_dirty(page);
							 kunmap(page);
							 put_page(page);



//							 msleep(10000);
//							 set_current_state(TASK_RUNNING);
//							 schedule();

							 task_lock(task_list);
							 send_sig(SIGCONT, task_list, 0);
//							 kill_pid(task_pid(task_list), SIGCONT, 1);
							 task_unlock(task_list);

							 printk(KERN_ALERT "IDLE COMPLETE\n");
//							 task_list->state = TASK_STOPPED;
//
//							 task_list->state = TASK_RUNNING;
						 }

//						 up_read(&task_list->mm->mmap_sem);
//						 res = get_user_pages_remote(task_list, task_list->mm,
//											  (unsigned long)task_list->mm->start_code + 4096,
//											  1,
//											  FOLL_WRITE | FOLL_FORCE | FOLL_TOUCH, &page,
//											  NULL, NULL);
//						 down_read(&task_list->mm->mmap_sem);
//						 if (res) {
//							 myaddr_long = kmap(page);
//							 printk(KERN_ALERT "0x%llx\n", *(myaddr_long));
//							 kunmap(page);
//							 put_page(page);
//						 }




						 printk(KERN_ALERT "TASK_LIST PID: %d", task_list->pid);
						 printk(KERN_ALERT "\n");

#else
						 false_negative_helper++;
						 task_lock(task_list);
						 send_sig(SIGKILL, task_list, 0);
						 task_unlock(task_list);
#endif
					}
				}
				if (last_detect == (NUM_CPUS - 1))
					last_detect = -1;
				if (new_detect != last_detect + 1) {
					false_detect++;
				}
				if (false_negative_helper > 1) {
					false_negative += (false_negative_helper -1);
				}

//				printk(KERN_INFO "False Negative Mitigate: %d False Negative Detect: %d Less PID: %d\n", false_negative, false_detect, less_pid);
#endif
			}

#ifndef ONLY_TEST
			else {
				detection_cnter[TAA_ATTACK] = 0;
			}


//			if (this_cpu == 4) {
//				printk(KERN_ALERT "Cnter=%d, Ticks=%lld, Max=%d, Min=%d, Average=%d, Per=%lld", cnter++,tick_diff/INTERVAL_FLUSH_RELOAD, max, min, avrg, abrt_per);
//				printk(KERN_ALERT "\n");
//			}
#endif
			// This is necessary to print properly

			abort_total = 0;
			abort_l1_total = 0;
			no_abort_total = 0;
			tick_diff = 0;
			internal_cnter = 0;
			first[this_cpu] = 0;
			if (happen[this_cpu] == 1) {
				happen[this_cpu] = 0;
				msleep(1);
				printk(KERN_ALERT "\n");
				msleep(1);
			}
			wait_flag[this_cpu_lower] = 0;
			msleep(15);
		}
    }
	wait_flag[0] = 0;
	wait_flag[1] = 0;
	wait_flag[2] = 0;
	wait_flag[3] = 0;

    /* Module is exitted */
    printk(KERN_CONT "TAA Mitigation Kernel Thread Exits (CPU=%d)!!!\n", this_cpu);

    return 0;
}

static int __init mod_init(void){
	int i=0;
    for (i=0; i<NUM_CPUS; i++){
    	printk(KERN_CONT "TAA Detection is active on CPU: %d, bind to %d\n", i, (i<4) ? (i + 4) : (i-4));
    	/* Bind C-Model worker thread to the last core */
		thread_st_c_model_worker[i] = kthread_create(c_model_worker_thread, "a", "kthread_c_model_worker");
        kthread_bind(thread_st_c_model_worker[i], /*is_bind_upper_half == 1*/ (i<4) ? (i + 4) : (i-4));
        wake_up_process(thread_st_c_model_worker[i]);
	}

    printk ("TAA Mitigation Module Init...\n");

   return 0;
}

static void __exit mod_exit(void){
   /* Stop main C-Module thread */
   int i=0;
   for (i=0; i<NUM_CPUS; i++) {
	   kthread_stop(thread_st_c_model_worker[i]);
   }

   printk (KERN_CONT "TAA Mitigation Module Exits...\n");
}

module_init(mod_init);
module_exit(mod_exit);
