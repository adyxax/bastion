#ifndef COMMON_DATA_H_
#define COMMON_DATA_H_

#include <libssh/server.h>

void data_clean(void);

struct data_host_info {
    const char * address;
    const char * username;
    ssh_key key;
    const char * pubkey;
};

const char * data_get_username_from_pubkey(ssh_key pubkey);
struct data_host_info * // returns NULL if no key found, this struct is to be freed from the calling code
data_get_host_info(const char * hostname);

#endif
