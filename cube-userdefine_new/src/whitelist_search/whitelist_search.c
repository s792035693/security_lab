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
#include "whitelist_search.h"
// add para lib_include
#define ELFMAG          "\177ELF"
#define SHELLMAG1          "#!/"
#define SHELLMAG2          "#! /"

int searchfile(char *dir,char * filename);
int is_exec(char *fn);
int entrydir(char *file,char * filename);
void dtof(char *file,char * filename);
//compare digest, 0: equal, 1: larger, -1: smaller
void sortfile(char * infile,  char *outfile);
int check_basewhitelist(RECORD(WHITELIST_SM3,BASE_WHITELIST) * base_whitelist);


int  compare(const void *a,const void *b)
{
	return Memcmp((unsigned char *)a,(unsigned char *)b,DIGEST_SIZE);
}


char * skip_dir[] = {
	"/proc", 			//skip
	"/sys", 
	"/dev",
	"/var/tmp",
	"/media/floppy",
	"/root/centoscloud",
	NULL
};

int whitelist_search_init(void * sub_proc, void * para)
{
	int ret;
	// add yorself's module init func here
	return 0;
}
int whitelist_search_start(void * sub_proc, void * para)
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
			proc_base_whitelist_gen(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_base_whitelist_gen( void * sub_proc, void * recv_msg)
{
	int ret,fd;
	RECORD(WHITELIST_SM3,BASE_WHITELIST) * base_whitelist;
	char uuid[DIGEST_SIZE*2+1];	
	char *temp_filename="whitelist_temp";

	ret=message_get_record(recv_msg,&base_whitelist,0);
	if(ret<0)
		return ret;
	if(base_whitelist==NULL)
		return -EINVAL;

	ret=check_basewhitelist(base_whitelist);
	if(ret==0)
	{	
		fd=open(temp_filename,O_WRONLY|O_CREAT|O_TRUNC,0666);
		if(fd<0)
			return fd;
		close(fd);
		ret=searchfile("/",temp_filename);

		if(ret>=0)
		{
			sortfile(temp_filename,temp_filename);
		}
		convert_uuidname(temp_filename,DIGEST_SIZE,base_whitelist->whitelist_uuid,uuid);
		memdb_store(base_whitelist,TYPE_PAIR(WHITELIST_SM3,BASE_WHITELIST),base_whitelist->whitelist_name);
	
	}
	else if(ret!=WHITELIST_CORRECT)
	{
		print_cubeerr("check base whitelist err %d!\n",ret);
		return ret;
	}


	void * send_msg = message_create(TYPE_PAIR(WHITELIST_SM3,BASE_WHITELIST),recv_msg);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,base_whitelist);
	ex_module_sendmsg(sub_proc,send_msg);	
	return 0;
}

int is_exec(char *fn)
{
	FILE *f;
	char buf[8];
	int ret=0;

	if ((f = fopen(fn, "r")) == NULL) {
		print_cubeerr("Cannot open `%s' .\n",fn);
		return -EINVAL;
	}

	if (fgets(buf, 8, f) != NULL) {
		if (!memcmp(buf,SHELLMAG1,strlen(SHELLMAG1)) 
				||!memcmp(buf,SHELLMAG2,strlen(SHELLMAG2))
				||!memcmp(buf,ELFMAG,strlen(ELFMAG)))
			ret=1;
	}
	else
		ret=0;
	fclose(f);
	return ret;
}

void dtof(char *file,char * digest_file)
{
	int i;
	int fd;
	BYTE result[DIGEST_SIZE];
	UINT32 results;
	struct stat attribute;
	fd=open(digest_file,O_WRONLY|O_APPEND);
	if(fd<0)
		return fd;
	
	if(lstat(file, &attribute)==-1)
	{
		print_cubeerr("lstat %s error\n",file);
		close(fd);
		return ;
	}
	if(attribute.st_size>0)
	{
		if (calculate_sm3(file,result))
  	  	{
			print_cubeerr("Error during sm3-calculation\n");
			close(fd);
			return ;
   	 	}
		//fwrite(&results,sizeof(uint32_t),1,output);
		write(fd,result,DIGEST_SIZE);
		memset(result,0,sizeof(result));
	}
	close(fd);
	return ;
}

int entrydir(char *file,char * digest_file)
{
	struct dirent *dt;
	DIR * dir;
	struct stat stat;
	size_t namelen,flen;
	int i = 0,mode=0;
	char *name=NULL,*suffix=NULL;

	for(i=0; skip_dir[i]!=NULL;i++)
	{
		if ( !Strncmp(file,skip_dir[i],Strlen(skip_dir[i]))) 			//skip
			return 0;
	}

	flen = strlen(file);
	dir = opendir(file);
	while(( dt = readdir(dir)) != NULL){

		name=dt->d_name;
		if (!Strcmp(name,".") || !Strcmp(name,".."))
			continue;

		namelen = Strlen(name);
		suffix=name+namelen-3;

		if ( !Strncmp(suffix,".ko",Strlen(".ko"))) //skip
			continue;
		if ( !Strncmp(suffix,".so",Strlen(".so"))) //skip
			continue;
		
		if(flen!=1){
			Strcat(file,"/");
		}
		Strcat(file,name);

		if (lstat(file,&stat) == -1){
			Memset(file+flen,0,namelen+1); //"/dt->name"
			print_cubeerr("%s\t lstat error\n",file);
			continue;
		}
		mode = stat.st_mode;
		if (S_ISREG(mode)){
			
			if (!Strncmp(suffix,".py",3)
					||!Strncmp(suffix,".pl",3)
					||mode & S_IXUSR
					||mode & S_IXGRP
					||mode & S_IXOTH)
			{
				//printf("%s\t is exec file\n",file);
				if(is_exec(file)){
					dtof(file,digest_file);
				}
			}
			
		}
		else if (S_ISDIR(mode)){
			
		//	printf("%s \t DIR\n",file);
		        printf(".");
			entrydir(file,digest_file);		
		}
		file[flen] = '\0';
	}
	
	closedir(dir);
	
	return 0;				
}

int searchfile(char *dir,char * digest_file)
{
	int ret;
	char dfile[PATH_MAX+32];
	struct stat stat;
	Memset(dfile,0,sizeof(dfile));
	Memcpy(dfile,dir,Strlen(dir));

	if (Strcmp(dfile,"/") && (dfile[strlen(dfile)-1] == '/')) 	//  input /usr/local/src/ -> /usr/local/src
		dfile[strlen(dfile)-1] = '\0';

	if (lstat(dfile,&stat) == -1){
		print_cubeerr("[%s] is lstat error\n",dfile);
		return -EINVAL;	
	}
	
	if (S_ISDIR(stat.st_mode)){
		ret=entrydir(dfile,digest_file);
		return ret;
	}
	if (S_ISREG(stat.st_mode)){
	         if ((stat.st_mode & S_IXUSR )|| (stat.st_mode & S_IXGRP )||( stat.st_mode & S_IXOTH)){
				//printf("%s\t is exec file\n",file);
			if(!is_exec(dfile)){
			     dtof(dfile,digest_file);
	                     return 0;
			}
			else{
				print_cubeerr("%s\t is not elf file\n",dfile);
				return 1;
	                        //goto out2;
	       	        }
		}
		else{
			print_cubeerr("%s\t is not exec file\n",dfile);
			return 1;
			//goto out2;
		    }
			
	}else {
		print_cubeerr("%s is not regule file\n",dfile);
		return 1;
	      }

	return ret;
}

void sortfile(char * infile,  char *outfile)
{
	int fdin, fdout;	

	long  len = 0;

	long  h = 0;
	int i,j;
	char *str;

	BYTE ** parray;
	BYTE * pa;
        struct stat attribute;
	unsigned int fsize;
	int number=0;


	fdin = open(infile,O_RDONLY);
	if (fdin<0)
	{
		print_cubeerr("open file %s failed!",infile);
		return;
	}

        if(fstat(fdin, &attribute)<0)
	{
                print_cubeerr("fstat %s error\n",infile);
		return ;
	}
        if(attribute.st_size<=0)
	{
                print_cubeerr("file %s size error\n",infile);
		return ;
	}

	fsize = attribute.st_size;
	if (((fsize%DIGEST_SIZE) == 0)&& fsize<(DIGEST_SIZE*40000))
		number = fsize /DIGEST_SIZE;
	else
	{
                print_cubeerr("file %s size %d error\n",infile,fsize);
		return ;
	}
/*
	parray=malloc(number*sizeof( BYTE *));
	if(parray==NULL)
	{
		print_cubeerr("alloc parray error!\n");
		return;
	}
*/
	pa=malloc(number*DIGEST_SIZE);
	if(pa==NULL)
	{
		print_cubeerr("alloc pa error!\n");
		free(parray);
		return ;
	}

//	for(i=0;i<number;i++)
//		parray[i]=pa+i*DIGEST_SIZE;

	len = read(fdin,pa,number*DIGEST_SIZE);
	print_cubeaudit("read digest file %ld\n",len);
	close(fdin);
	fdout = open(outfile,O_WRONLY|O_CREAT|O_TRUNC,0666);
	if ((len >1)&&(len%DIGEST_SIZE==0))
	{
		qsort(pa,number,DIGEST_SIZE,compare);
	}
	else
	{
		print_cubeerr("file length error[%ld]!!\n",len);
		close(fdout);
		free(pa);
//		free(parray);
		return;
	}
	write(fdout,pa,number*DIGEST_SIZE);
	close(fdout);
	free(pa);
//	free(parray);
	return;
}

int check_basewhitelist(RECORD(WHITELIST_SM3,BASE_WHITELIST) * base_whitelist)
{
	int ret;
	DB_RECORD * db_record;
	BYTE empty_digest[DIGEST_SIZE];
	char uuid[DIGEST_SIZE*2+1];		
	RECORD(WHITELIST_SM3,BASE_WHITELIST) * compare_whitelist;
	if(base_whitelist==NULL)
		return 0;
	db_record=memdb_find_first(TYPE_PAIR(WHITELIST_SM3,BASE_WHITELIST),"whitelist_name",base_whitelist->whitelist_name);
	if(db_record==NULL)
		return 0;
	if(!Isemptyuuid(base_whitelist->whitelist_uuid))
	{
		compare_whitelist=db_record->record;
		if(!Memcmp(compare_whitelist->whitelist_uuid,base_whitelist->whitelist_uuid,DIGEST_SIZE))
			return WHITELIST_CORRECT;
		return WHITELIST_MISMATCH;
	}
	else
	{
		compare_whitelist=db_record->record;
		digest_to_uuid(base_whitelist->whitelist_uuid,uuid);
		uuid[DIGEST_SIZE*2]=0;
		if(access(uuid,O_RDONLY)==-1)
		{
			if(errno==ENOENT)
			{
				memdb_remove_record(db_record);
				return 0;
			}
			else
				return -EIO;
		}
		Memcpy(base_whitelist->whitelist_uuid,compare_whitelist->whitelist_uuid,DIGEST_SIZE);
	}
	return WHITELIST_CORRECT;
}
