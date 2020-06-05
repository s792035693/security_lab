enum dtype_whitelist_sm3 {
	TYPE(WHITELIST_SM3)=0x3501
};
enum subtype_whitelist_sm3 {
	SUBTYPE(WHITELIST_SM3,BASE_WHITELIST)=0x1,
	SUBTYPE(WHITELIST_SM3,PACKAGE_WHITELIST),
	SUBTYPE(WHITELIST_SM3,WHITELIST_ACTION),
	SUBTYPE(WHITELIST_SM3,WHITELIST_POLICY),
	SUBTYPE(WHITELIST_SM3,FILE_DIGEST)
};
enum whitelist_action
{
	WHITELIST_SELECT=1,
	WHITELIST_ADD,
	WHITELIST_DEL	
};

enum whitelist_checkresult
{
	WHITELIST_CORRECT=1,
	WHITELIST_NOTEXIST,
	WHITELIST_MISMATCH,
};


typedef struct base_whitelist_sm3{
	char * whitelist_name;
	char * os_type;
	char * os_version;
	char * implement_type;
	BYTE whitelist_uuid[32];
}__attribute__((packed)) RECORD(WHITELIST_SM3,BASE_WHITELIST);

typedef struct package_whitelist_sm3{
	char * whitelist_name;
	char * package_type;
	char * package_version;
	char * install_type;
	BYTE whitelist_uuid[32];
}__attribute__((packed)) RECORD(WHITELIST_SM3,PACKAGE_WHITELIST);

typedef struct whitelist_action_sm3{
	BYTE origin_uuid[32];
	BYTE select_uuid[32];
	enum whitelist_action action;
	BYTE result_uuid[32];
}__attribute__((packed)) RECORD(WHITELIST_SM3,WHITELIST_ACTION);

typedef struct whitelist_policy_sm3{
	char * base_policy;
	int add_policy_num;
	char * add_policys;
	int del_policy_num;
	char * del_policys;
}__attribute__((packed)) RECORD(WHITELIST_SM3,WHITELIST_POLICY);

typedef struct whitelist_file_digest{
	char * file_name;
	BYTE file_digest[DIGEST_SIZE];
	enum whitelist_checkresult check_result;
}__attribute__((packed)) RECORD(WHITELIST_SM3,FILE_DIGEST);
