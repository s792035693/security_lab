#ifndef POLICYMANAGE_H

#define POLICYMANAGE_H

#define HASHLIST_PATH 			"/boot/os_safe.d/whitelist"

#define MAXLIST 		 20000

//operation
//extern rwlock_t policy_rwlock;
//extern int read_config_flag;

/*
#define POLICY_WRITE_LOCK()		do{write_lock(&(policy_rwlock));}while(0);
#define POLICY_WRITE_UNLOCK()	do{write_unlock(&(policy_rwlock));}while(0);
#define POLICY_READ_LOCK()		do{read_lock(&(policy_rwlock));}while(0);
#define POLICY_READ_UNLOCK()		do{read_unlock(&(policy_rwlock));}while(0);
*/

int read_whitelist(const char * filename,const int max_number, int size);
void free_whitelist(void);
int alg_file_digest (struct file *fp,unsigned char xh_digest[DIGEST_SIZE]);

void * appbsearch(const void *key, const void *base, size_t nmemb, size_t size,
		int (*compar)(const void *, const void *));

int pm_check_fs_integrity(struct file *fp);

#endif

