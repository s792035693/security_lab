#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
 
#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"

#include "whitelist_struct.h"
#include "whitelist_load.h"
// add para lib_include
struct policy_buffer
{
	int digest_num;
	int digest_size;
	BYTE * digest_array;
} * policy_buffer;

int  proc_whitelist_search(void * sub_proc,void *recv_msg);
int  proc_whitelist_load(void * sub_proc,void *recv_msg);
BYTE * read_whitelist(const char * filename,const int max_number, int size);

static int compare_hash(const void *a,const void *b)
{
	return memcmp(a,b,DIGEST_SIZE);
}
void * appbsearch(const void *key, const void *base, size_t nmemb, size_t size,
		int (*compar)(const void *, const void *));


int whitelist_load_init(void * sub_proc, void * para)
{
	int ret;
	// add yorself's module init func here
	proc_share_data_setpointer(NULL);
	policy_buffer=NULL;
	return 0;
}
int whitelist_load_start(void * sub_proc, void * para)
{
	int ret;
	void * recv_msg;
	int type;
	int subtype;
	// add yorself's module exec func here
	while(1)
	{
		usleep(time_val.tv_usec);
		ret=ex_module_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_type(recv_msg);
		subtype=message_get_subtype(recv_msg);
		if(!memdb_find_recordtype(type,subtype))
		{
			printf("message format (%d %d) is not registered!\n",
			message_get_type(recv_msg),message_get_subtype(recv_msg));
			continue;
		}
		if((type==TYPE(WHITELIST_SM3)) && (subtype==SUBTYPE(WHITELIST_SM3,BASE_WHITELIST)))
		{
			proc_whitelist_load(sub_proc,recv_msg);
		}
		else if((type==TYPE(WHITELIST_SM3)) && (subtype==SUBTYPE(WHITELIST_SM3,FILE_DIGEST)))
		{
			proc_whitelist_search(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_whitelist_load(void * sub_proc,void * recv_msg)
{
	
	int ret,fd;
	char uuid[DIGEST_SIZE*2];
	RECORD(WHITELIST_SM3,BASE_WHITELIST) * load_whitelist;
	void * new_msg;

	ret=message_get_record(recv_msg,&load_whitelist,0);
	if(ret<0)
		return ret;

	digest_to_uuid(load_whitelist->whitelist_uuid,uuid);
	uuid[DIGEST_SIZE*2]=0;
	policy_buffer=read_whitelist(uuid,20000,DIGEST_SIZE);
	proc_share_data_setpointer(policy_buffer);

	new_msg=recv_msg;
        message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);
        ret=ex_module_sendmsg(sub_proc,new_msg);

	return 0;
}

int  proc_whitelist_search(void *sub_proc,void *recv_msg)
{
	int ret,fd;
	RECORD(WHITELIST_SM3,FILE_DIGEST) * file_digest;
	void * new_msg;
	struct policy_buffer * policys;

	ret=message_get_record(recv_msg,&file_digest,0);
	if(ret<0)
		return ret;

	policys=proc_share_data_getpointer();
	if(policys==NULL)
		return -EINVAL;

	if (!appbsearch(file_digest->file_digest,policys->digest_array,policys->digest_num,DIGEST_SIZE, compare_hash))
	{
		file_digest->check_result=WHITELIST_CORRECT;
	}
	else
		file_digest->check_result=WHITELIST_MISMATCH;

	new_msg=message_create(TYPE_PAIR(WHITELIST_SM3,FILE_DIGEST),recv_msg);
	message_add_record(new_msg,file_digest);
	ex_module_sendmsg(sub_proc,new_msg);
	return 0;
}

BYTE * read_whitelist(const char * filename,const int max_number, int size)
{

	int ret=0,i = 0;
	int fd;

	unsigned int fsize;
	int number = 0;

        struct stat attribute;
	struct policy_buffer * policys;

	fd=open(filename,O_RDONLY);

	if(fd<0) {
		print_cubeerr("open policy file %s error!",filename);
		return NULL;
	}
        if(fstat(fd, &attribute)<0)
	{
                printf("fstat error\n");
		return NULL;
	}
        if(attribute.st_size<=0)
		return NULL;

	fsize = attribute.st_size;
	if (((fsize%size) == 0)&& fsize<(32*max_number))
		number = fsize /size;
	else
		return NULL;

        print_cubeaudit("read hashlist app num is %d max %d\n",number,max_number);
	
	policys=malloc(sizeof(*policy_buffer));
	if(policys==NULL)
		return NULL;
	policys->digest_num=number;
	policys->digest_size=size;
	policys->digest_array=malloc(number*size);
	if(policys->digest_size==NULL)
	{
		free(policys);
		return NULL;
	}	
	
	memset(policys->digest_array,0,policys->digest_num*policys->digest_size);

	for (i=0;i<number;i++){
		ret=read(fd,policys->digest_array+size*i,size);
			
		if(ret!=size) {
			print_cubeerr("read [%s] error!\n",filename);
			free(policys->digest_array);
			free(policys);
			return NULL;
		}
	}
	return policys;
}

void * appbsearch(const void *key, const void *base, size_t nmemb, size_t size,
		int (*compar)(const void *, const void *))
{
	const void *entry;
	unsigned int l;
	unsigned int u;
	unsigned int m;

	BYTE * testbuf=key;

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
