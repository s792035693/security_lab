#include <scheme.h>
#include "data_type.h"
#include "crypto_func.h"
#include "sm3.h"
#include "policymanage.h"
#define f_dentry        f_path.dentry

int deep_debug=0;

static struct policy_buffer
{
	int digest_num;
	int digest_size;
	BYTE * digest_array;
} my_policy_buffer;

static int
compare_hash(const void *a,const void *b)
{
//	if(!memcmp(a,b,DIGEST_LEN))
//		printk("same!\n");
//	else
//		printk("not same !\n");
        if(deep_debug)
	{
		unsigned char * test_buf=b;
		printk("debug compare_hash %x %x %x\n",test_buf[0],test_buf[1],test_buf[2]);
	}
	return memcmp(a,b,DIGEST_SIZE);
}

int read_whitelist(const char * filename,const int max_number, int size)
{

	struct policy_buffer * policys=&my_policy_buffer;
	struct file * fp;
	mm_segment_t oldfs;
	char * kernel_buffer;
	int ret=0,i = 0;

	unsigned int fsize;
	int number = 0;

	policys->digest_size=size;
 	
	fp = filp_open(filename,O_RDONLY,0);
	if(IS_ERR(fp) || fp == NULL ) {
		printk("open policy file %s error!",filename);
		return -1;
	}
	
	fsize = fp->f_dentry->d_inode->i_size;
	if (((fsize%size) == 0)&& fsize<(32*40000))
		number = fsize /size;
	else
		goto out1;
        printk("read hashlist app num is %d max %d\n",number,max_number);
	
	policys->digest_num=number;
	policys->digest_array=kmalloc(size*number,GFP_KERNEL);
	if(!policys->digest_array)
	{
		printk("alloc digest policy buffer error!\n");
		return -ENOMEM;
		memset(policys->digest_array,0,policys->digest_num*policys->digest_size);
	}

	kernel_buffer=  kmalloc(size,GFP_KERNEL);
	//memset(user_buffer,0,size);
	if(!kernel_buffer) {	
		printk("alloc mem for read config file err!\n");
		return -ENOMEM;	
	}


	oldfs = get_fs();
	set_fs (KERNEL_DS);


	
	for (i=0;i<number;i++){
		ret=vfs_read(fp,kernel_buffer,size,&fp->f_pos);
			
		if(ret!=size) {
			printk("read [%s] error!\n",filename);
			goto out2;		
		}
		memcpy(policys->digest_array+size*i,kernel_buffer,size);	
	
	}
//        printk("free \n");	
	kfree(kernel_buffer);
	set_fs(oldfs);
	filp_close(fp,0);
	return 0;
out2:
        printk("out 2\n");
	kfree(kernel_buffer);
	set_fs(oldfs);
out1:
        printk("out 1\n");
	filp_close(fp,0);
	printk("[%s] formt error\n",filename);
	
}

extern unsigned long volatile jiffies;

void free_whitelist()
{
	struct policy_buffer * policys=&my_policy_buffer;
	if(!policys->digest_array)
		kfree(policys->digest_array);
	policys->digest_array=NULL;
	policys->digest_num=0;	
}

int alg_file_digest (struct file *fp,unsigned char xh_digest[DIGEST_SIZE])
{
	int i;
	sm3_context context;
	mm_segment_t oldfs;
	int len;

	unsigned char *kern_buf;
	loff_t pos = 0;

	if(IS_ERR(fp) || fp == NULL ) {
		printk("alg_check fp is null\n");		
		return -1;
		}	
	SM3_init(&context);
	pos=fp->f_pos;
	fp->f_pos=0;
	kern_buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
	oldfs = get_fs();
	set_fs (KERNEL_DS);
	len = vfs_read (fp,kern_buf, PAGE_SIZE,&fp->f_pos);
	while (len > 0)
	{
		SM3_update (&context, kern_buf, len);
		len = vfs_read (fp,kern_buf, PAGE_SIZE,&fp->f_pos);
	}
	set_fs(oldfs);
	SM3_final(&context,xh_digest);
	kfree(kern_buf);

	fp->f_pos = pos;
	return 0;

}

// found return entry;non-found return NULl
void *
appbsearch(const void *key, const void *base, size_t nmemb, size_t size,
		int (*compar)(const void *, const void *))
{
	const void *entry;
	unsigned int l;
	unsigned int u;
	unsigned int m;

	l = -1;
	u = nmemb;
	while (l + 1 != u) {
		m = (l + u) / 2;
		entry = base + m * size;
		if (compar(key, entry) > 0)
			l = m;
		else
			u = m;
	}

	entry = base + u * size;
	//printk("num:%d,dig_size:%d\n",nmemb,size);
	if (u == nmemb
			|| compar(key, entry) != 0)
		return (NULL);

	return ((void *)entry);
}

int pm_check_fs_integrity(struct file *fp)
{
	unsigned char digest[DIGEST_SIZE];
    //unsigned char digest_xor[4];
	int ret = 0;
	if (!fp)
		goto out;
	alg_file_digest(fp,digest);
	if(deep_debug)
		printk("debug file hash  %x %x %x\n",digest[0],digest[1],digest[2]);
	if (!appbsearch(digest,my_policy_buffer.digest_array,my_policy_buffer.digest_num,DIGEST_SIZE, compare_hash)){
		ret = -1;
	}
out:
	return ret;
}
