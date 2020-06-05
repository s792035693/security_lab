#include <scheme.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/uaccess.h>  
#include <linux/kallsyms.h>
#include "data_type.h"
#include "policymanage.h"
			
extern int deep_debug;

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
               	ret = 1;
       	}
//		deep_debug=0;
        return ret;
}

static struct security_operations ** security_ops_addr = NULL; 
static struct security_operations * old_hooks = NULL;
static struct security_operations new_hooks = {0};

static inline void __hook(void)
{
	memcpy(&new_hooks, old_hooks, sizeof(new_hooks));

	new_hooks.bprm_check_security = os_bprm_check_security;

	*security_ops_addr = &new_hooks;
}

static inline void __unhook(void)
{
	if (old_hooks) {
		*security_ops_addr = old_hooks;
	}
}
 
static int __init xsec_init(void)
{
	int retval = -EINVAL;
	int idx = 0;

	security_ops_addr = (struct security_operations **)kallsyms_lookup_name("security_ops");
 
	if (!security_ops_addr){
		printk("no security hook heads \n");
		goto DONE;
	}
	printk ("security ops addr is %p\n", security_ops_addr);
	retval=read_whitelist(HASHLIST_PATH,MAXLIST,DIGEST_SIZE);
	if(retval)
	{
		printk("read whitelist error %d\n",retval);
		return retval;
	}


	old_hooks = *security_ops_addr;
	
	printk ("security old ops is %p\n", old_hooks);

	__hook();

	printk ("new hooks ops is  %p\n", &new_hooks);
	printk ("security new ops is %p\n", *security_ops_addr);
	
	retval = 0;
DONE:
 
	return retval;
}

static void __exit xsec_exit(void)
{
	__unhook();
	
	return;	
}

module_init(xsec_init);
module_exit(xsec_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("xssr-core-driver");  
MODULE_VERSION("1.0.1");  
MODULE_ALIAS("xssr");  
MODULE_AUTHOR("yq-tech");  

