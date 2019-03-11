#ifndef COMMON_MYSQL_H_
#define COMMON_MYSQL_H_

struct db_host_info {
    char * privkeytxt;
    char * address;
    char * username;
    char * hostkeyhash;
};

char db_init(void);
void db_clean(void);
char * // returns NULL if no user found, this char * is to be freed from the calling code
db_get_username_from_pubkey(ssh_key pubkey);
struct db_host_info * // returns NULL if no key found, this char * is to be freed from the calling code
db_get_host_info(const char * hostname);
void db_set_host_publickey_hash(const char * hostname, const char * hash);
unsigned long long // returns 0 on error, or the session_id
db_init_session_and_get_id(const char * hostname, const char * username);
void db_free_host_info(struct db_host_info * info);

#endif
