#ifndef MYSQL_H_
#define MYSQL_H_

struct db_host_info {
    char * privkeytxt;
    char * address;
    char * username;
    char * hostkeyhash;
};

char db_init(void);
void db_clean(void);
char * db_get_username_from_pubkey(ssh_key pubkey);
struct db_host_info * db_get_host_info(const char * hostname);
void db_free_host_info(struct db_host_info * info);
void db_set_host_publickey_hash(const char * hostname, const char * hash);

#endif
