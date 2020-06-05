#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
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
#include "whitelist_check.h"
// add para lib_include
int whitelist_check_init(void * sub_proc, void * para)
{
	int ret;
	// add yorself's module init func here
	return 0;
}
int whitelist_check_start(void * sub_proc, void * para)
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
		if((type==TYPE(MESSAGE) && subtype==SUBTYPE(MESSAGE,BASE_MSG)))
		{
			proc_whitelist_filecheck(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_whitelist_filecheck(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(MESSAGE,BASE_MSG) * filename_msg;
	RECORD(WHITELIST_SM3,FILE_DIGEST) * file_digest;
	void * new_msg;

	ret=message_get_record(recv_msg,&filename_msg,0);
	if(ret<0)
		return ret;
	if(filename_msg==NULL)
		return -EINVAL;
	
	file_digest=Talloc0(sizeof(*file_digest));
	if(file_digest==NULL)
		return -ENOMEM;
	
	file_digest->file_name=dup_str(filename_msg->message,0);	
	calculate_sm3(file_digest->file_name,file_digest->file_digest);
	new_msg=message_create(TYPE_PAIR(WHITELIST_SM3,FILE_DIGEST),recv_msg);
	if(new_msg==NULL)
		return -EINVAL;
	
	message_add_record(new_msg,file_digest);
	ex_module_sendmsg(sub_proc,new_msg);
	return 0;
}
