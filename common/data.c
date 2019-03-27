#include <ctype.h>
#include <libconfig.h>
#include <libssh/libssh.h>
#include <uthash.h>

#include "config.h"
#include "data_for_config.h"

struct key {
    const char *name;          // key
    ssh_key key;
    UT_hash_handle hh;         // makes this structure hashable
};

struct user {
    const char *name;          // key for hh_user
    const char *pubkeystr;        // key for hh_pubkey
    UT_hash_handle hh_user, hh_pubkey;         // makes this structure hashable, twice
};

struct host {
    const char *name;
    const char *address;
    const char *user;
    ssh_key key;
    const char *pubkeystr;
    UT_hash_handle hh;         // makes this structure hashable
};

struct key * keys = NULL;
struct user * users = NULL;
struct user * pubkeys = NULL;
struct host *hosts = NULL;

char  // returns 0 if ok, something else otherwise
data_init(const config_t * config)
{
    config_setting_t *setting;
    const int config_dir_len = strlen(CONFIG_DIR);

    // We load the ssh keys in the hastable
    setting = config_lookup(config, "hostkeys");
    if(setting != NULL) {
        int count = config_setting_length(setting);
        for(int i = 0; i < count; ++i) {
            config_setting_t *elt = config_setting_get_elem(setting, i);
            const char *name, *key_path;
            if (config_setting_lookup_string(elt, "name", &name) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid key entry with no name.\n");
                return 1;
            }
            struct key * tmp;
            HASH_FIND_STR(keys, name, tmp);
            if (tmp != NULL) {
                fprintf(stderr, "Invalid key with duplicate name %s.\n", name);
                return 1;
            }
            if (config_setting_lookup_string(elt, "path", &key_path) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid key entry %s with no path.\n", name);
                return 1;
            }
            tmp = malloc(sizeof(struct key));
            tmp->name = name;
            char * key_realpath = malloc(strlen(key_path) + config_dir_len + 1);
            strcpy(key_realpath, CONFIG_DIR);
            strcpy(key_realpath + config_dir_len, key_path);
            switch(ssh_pki_import_privkey_file(key_realpath, NULL, NULL, NULL, &tmp->key)) {
              case SSH_EOF:
                fprintf(stderr, "Error importing ssh key from file %s : file doesn't exist or permission denied.\n", key_realpath);
                free(key_realpath);
                free(tmp);
                return 1;
                break;
              case SSH_ERROR:
                fprintf(stderr, "Error importing ssh key from file %s.\n", key_realpath);
                free(key_realpath);
                free(tmp);
                return 1;
                break;
              case SSH_OK:
                break;
            }
            HASH_ADD_KEYPTR(hh, keys, tmp->name, strlen(tmp->name), tmp);
            free(key_realpath);
        }
    }

    // We load the users in the hastable
    setting = config_lookup(config, "users");
    if(setting != NULL) {
        int count = config_setting_length(setting);
        for(int i = 0; i < count; ++i) {
            config_setting_t *elt = config_setting_get_elem(setting, i);
            const char *name, *pubkeystr;
            if (config_setting_lookup_string(elt, "name", &name) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid user entry with no name.\n");
                return 1;
            }
            unsigned int name_len = strlen(name);
            struct user * tmp;
            HASH_FIND(hh_user, users, name, name_len, tmp);
            if (tmp != NULL) {
                fprintf(stderr, "Invalid user with duplicate name %s.\n", name);
                return 1;
            }
            if (config_setting_lookup_string(elt, "public_key", &pubkeystr) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid user entry %s with no public_key.\n", name);
                return 1;
            }
            // TODO support other key types
            // And find a cleaner way to strip this key header before importing, and store a type flag
            char * rsa = "ssh-rsa ";
            pubkeystr += strlen(rsa);
            unsigned int pubkeystr_len = strlen(pubkeystr);
            for (unsigned int i = 0; i < pubkeystr_len; ++i) {
                if (isspace(pubkeystr[i]) == 0)
                    continue;
                fprintf(stderr, "Invalid trailing characters in public key for user %s :%s.\n", name, pubkeystr+i);
                return 1;
            }
            HASH_FIND(hh_pubkey, pubkeys, pubkeystr, pubkeystr_len, tmp);
            if (tmp != NULL) {
                fprintf(stderr, "Invalid user %s with duplicate public_key with %s.\n", name, tmp->name);
                return 1;
            }
            ssh_key tmpkey;
            switch(ssh_pki_import_pubkey_base64(pubkeystr, SSH_KEYTYPE_RSA, &tmpkey)) {
              case SSH_ERROR:
                fprintf(stderr, "Error importing public key for user %s.\n", name);
                return 1;
                break;
              case SSH_OK:
                ssh_key_free(tmpkey);
                break;
            }
            tmp = malloc(sizeof(struct user));
            tmp->name = name;
            tmp->pubkeystr = pubkeystr;
            HASH_ADD_KEYPTR(hh_user, users, tmp->name, name_len, tmp);
            HASH_ADD_KEYPTR(hh_pubkey, pubkeys, tmp->pubkeystr, pubkeystr_len, tmp);
        }
    }

    // We load the hosts in the hastable
    setting = config_lookup(config, "hosts");
    if(setting != NULL) {
        int count = config_setting_length(setting);
        for(int i = 0; i < count; ++i) {
            config_setting_t *elt = config_setting_get_elem(setting, i);
            const char *name, *address, *user, *hostkey, *pubkeystr;
            if (config_setting_lookup_string(elt, "name", &name) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid host entry with no name.\n");
                return 1;
            }
            struct host * tmp;
            HASH_FIND_STR(hosts, name, tmp);
            if (tmp != NULL) {
                fprintf(stderr, "Invalid host with duplicate name %s.\n", name);
                return 1;
            }
            if (config_setting_lookup_string(elt, "address", &address) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid host entry %s with no address.\n", name);
                return 1;
            }
            if (config_setting_lookup_string(elt, "user", &user) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid host entry %s with no user.\n", name);
                return 1;
            }
            if (config_setting_lookup_string(elt, "hostkey", &hostkey) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid host entry %s with no ssh_key.\n", name);
                return 1;
            }
            struct key * key;
            HASH_FIND_STR(keys, hostkey, key);
            if (key == NULL) {
                fprintf(stderr, "Host key \"%s\" was not found for host \"%s\".\n", hostkey, name);
                return 1;
            }
            if (config_setting_lookup_string(elt, "public_key", &pubkeystr) == CONFIG_FALSE) {
                fprintf(stderr, "Invalid user entry %s with no public_key.\n", name);
                return 1;
            }
            // TODO support other key types
            // And find a cleaner way to strip this key header before importing, and store a type flag
            char * ecdsa = "ssh-ed25519 ";
            pubkeystr += strlen(ecdsa);
            unsigned int pubkeystr_len = strlen(pubkeystr);
            for (unsigned int i = 0; i < pubkeystr_len; ++i) {
                if (isspace(pubkeystr[i]) == 0)
                    continue;
                fprintf(stderr, "Invalid trailing characters in public key for user %s :%s.\n", name, pubkeystr+i);
                return 1;
            }
            ssh_key tmpkey;
            switch(ssh_pki_import_pubkey_base64(pubkeystr, SSH_KEYTYPE_ED25519, &tmpkey)) {
              case SSH_ERROR:
                fprintf(stderr, "Error importing public key for user %s.\n", name);
                free(tmp);
                return 1;
                break;
              case SSH_OK:
                ssh_key_free(tmpkey);
                break;
            }
            tmp = malloc(sizeof(struct host));
            tmp->name = name;
            tmp->address = address;
            tmp->user = user;
            tmp->key = key->key;
            tmp->pubkeystr = pubkeystr;
            HASH_ADD_KEYPTR(hh, hosts, tmp->name, strlen(tmp->name), tmp);
        }
    }

    return 0;
}

void data_clean(void)
{
    struct key *current_key, *tmp_key;

    HASH_ITER(hh, keys, current_key, tmp_key) {
        HASH_DEL(keys, current_key);
        ssh_key_free(current_key->key);
        free(current_key);
    }

    HASH_CLEAR(hh_user, users);

    struct user *current_pubkey, *tmp_pubkey;
    HASH_ITER(hh_pubkey, pubkeys, current_pubkey, tmp_pubkey) {
        HASH_DELETE(hh_pubkey, pubkeys, current_pubkey);
        free(current_pubkey);
    }

    struct host *current_host, *tmp_host;
    HASH_ITER(hh, hosts, current_host, tmp_host) {
        HASH_DEL(hosts, current_host);
        free(current_host);
    }
}

const char * // returns NULL if no user found
data_get_username_from_pubkey(ssh_key pubkey)
{
    const char *username = NULL;
    char *pubkeystr;
    if (ssh_pki_export_pubkey_base64(pubkey, &pubkeystr) != SSH_OK) {
        fprintf(stderr, "Got invalid public key from auth attempt, this shouldn't happen.\n");
        return NULL;
    }
    unsigned int pubkeystr_len = strlen(pubkeystr);
    struct user *tmp;
    HASH_FIND(hh_pubkey, pubkeys, pubkeystr, pubkeystr_len, tmp);
    if (tmp != NULL) {
        username = tmp->name;
    }
    free(pubkeystr);
    return username;
}

struct data_host_info * // returns NULL if no key found, this struct is to be freed from the calling code
data_get_host_info(const char * hostname)
{
    struct host * tmp;
    HASH_FIND_STR(hosts, hostname, tmp);
    if (tmp != NULL) {
        struct data_host_info *info = malloc(sizeof(struct data_host_info));
        info->address = tmp->address;
        info->username = tmp->user;
        info->key = tmp->key;
        info->pubkey = tmp->pubkeystr;
        return info;
    }
    return NULL;
}
