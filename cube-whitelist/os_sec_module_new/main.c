#include <scheme.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/uaccess.h>  
#include <linux/kallsyms.h>
#include <linux/lsm_hooks.h>
#include "data_type.h"
#include "policymanage.h"
			
extern int deep_debug;
struct security_hook_heads test_security_hook_heads;

static int test_mmap_file(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags)
{
	printk("test-mmap-file......\n"); 
	return 0;
}

static int os_bprm_check_security (struct linux_binprm *bprm)
{
	int ret=0;
//	if(!strcmp(bprm->filename,"/usr/bin/ls"))
//		deep_debug=1;

  //             	printk(KERN_EMERG"(2) test exec file %s \n",bprm->filename);
       	if (pm_check_fs_integrity(bprm->file)){
               	printk(KERN_EMERG"(2) %s is not in the whitelist!!!\n",bprm->filename);
               	ret = 0;
       	}
//		deep_debug=0;
        return ret;
}

static struct security_hook_list test_hooks[] = {
	{ .head = &test_security_hook_heads.bprm_check_security,	\
			.hook = { .bprm_check_security = os_bprm_check_security } }
	
};

 
#define MAX_RO_PAGES 1024
static struct page *ro_pages[MAX_RO_PAGES];
static unsigned int ro_pages_len = 0;

static bool __init __test_ro_page(void *addr)
{
	unsigned int i;
	int unused;
	struct page *page;

	page = (struct page *) lookup_address((unsigned long) addr, &unused);
	if (!page)
		return -1;
	if (test_bit(_PAGE_BIT_RW, &(page->flags)))
		return 0;
	for (i = 0; i < ro_pages_len; i++)
		if (page == ro_pages[i])
			return 0;
	if (ro_pages_len == MAX_RO_PAGES)
		return -1;
	ro_pages[ro_pages_len++] = page;
	return 0;
}

static bool __check_pages(struct security_hook_heads *hooks)
{
	int i;
	struct list_head *list = (struct list_head *) hooks;

	if (!probe_kernel_write(&list->next, list->next, sizeof(void *)))
		return 0;
	for (i = 0; i < ARRAY_SIZE(test_hooks); i++) {
		const unsigned int idx =
			((unsigned long) test_hooks[i].head
			 - (unsigned long) hooks)
			/ sizeof(struct list_head);
		struct list_head * __entry = &list[idx];
		struct list_head * __prev = __entry->prev;

		if (0 != __test_ro_page(&__prev->next) ||
		    0 != __test_ro_page(&__entry->prev))
			return -1;
		if (!list_empty(__entry) &&
		    0 != __test_ro_page(&list_last_entry
				      (__entry, struct security_hook_list,
				       list)->hook))
			return -1;
	}
	return 0;
}

static inline void __hook(struct security_hook_list *hook)
{
	list_add_tail_rcu(&hook->list, hook->head);
}
/*
static struct security_operations ** security_ops_addr = NULL; 
static struct security_operations * old_hooks = NULL;
static struct security_operations new_hooks = {0};
*/
/*
static inline void __hook(void)
{
	memcpy(&new_hooks, old_hooks, sizeof(new_hooks));

	new_hooks.bprm_check_security = os_bprm_check_security;

	*security_ops_addr = &new_hooks;
}
*/
/*
static inline void __unhook(void)
{
	if (old_hooks) {
		*security_ops_addr = old_hooks;
	}
}
*/
static int __init xsec_init(void)
{
	int retval = -EINVAL;
	int idx ;

	struct security_hook_heads * hooks = (struct security_hook_heads *)kallsyms_lookup_name("security_hook_heads"); //-- ;// -- probe_security_hook_heads();
 
	retval=read_whitelist(HASHLIST_PATH,MAXLIST,DIGEST_SIZE);
	if(retval)
	{
		printk("read whitelist error %d\n",retval);
		return retval;
	}

	if (!hooks)
	{
		printk("no security hook heads \n");
		free_whitelist(); 
		return retval;
	}

	for (idx = 0; idx < ARRAY_SIZE(test_hooks); idx++){
		test_hooks[idx].head = ((void *) hooks)
			+ ((unsigned long) test_hooks[idx].head)
			- ((unsigned long) &test_security_hook_heads);
	}
	if (0 != __check_pages(hooks)) {
		free_whitelist(); 
		return retval;
	}
 
	for (idx = 0; idx < ro_pages_len; idx++){
		set_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags));
	}
	
	for (idx = 0; idx < ARRAY_SIZE(test_hooks); idx++){
		__hook(&test_hooks[idx]);
	}
	
 
	for (idx = 0; idx < ro_pages_len; idx++){
		clear_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags));
	}
 
	retval = 0;
	return retval;
}

static void __exit xsec_exit(void)
{
	int idx;
	
	for (idx = 0; idx < ro_pages_len; idx++){
		set_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags));
	}
	
	for (idx = 0; idx < ARRAY_SIZE(test_hooks); idx++){
		list_del_rcu(&test_hooks[idx].list);
	}	
	
	for (idx = 0; idx < ro_pages_len; idx++){
		clear_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags));
	} 
	free_whitelist();
	
	return ;	
}

module_init(xsec_init);
module_exit(xsec_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("xssr-core-driver");  
MODULE_VERSION("1.0.1");  
MODULE_ALIAS("xssr");  
MODULE_AUTHOR("yq-tech");  

