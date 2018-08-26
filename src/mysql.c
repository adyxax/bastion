#include <libssh/server.h>
#include <mysql/mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../config.h"
#include "mysql.h"

static MYSQL *db;

char // returns 0 if ok, greater than 0 otherwise
db_init(void)
{
    printf("MySQL client version: %s\n", mysql_get_client_info());
    db = mysql_init(NULL);
    if (db == NULL) {
        fprintf(stderr, "%s\n", mysql_error(db));
        return 1;
    }
    if (mysql_real_connect(db, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB, 0, NULL, 0) == NULL) {
        fprintf(stderr, "%s\n", mysql_error(db));
        mysql_close(db);
        return 1;
    }
    return 0;
}

void db_clean(void)
{
    mysql_close(db);
    db = NULL;
}

char * // returns NULL if no user found, this char * is to be freed from the calling code
db_get_username_from_pubkey(ssh_key pubkey)
{
    int res = mysql_query(db, "SELECT name, authorized_key FROM users, user_keys WHERE users.id = user_keys.user_id");
    if (res != 0) {
        fprintf(stderr, "WARNING: Couldn't get usernames from database.\n");
        return NULL;
    }
    MYSQL_RES *result = mysql_store_result(db);
    if (result == NULL) {
        fprintf(stderr, "FATAL: Couldn't retrieve public keys from database.\n");
        return NULL;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        char * rsa = "ssh-rsa ";
        if (strncmp (row[1], rsa, strlen(rsa)) != 0) {
            fprintf(stderr, "Unsupported public key type for user %s : %s\n", row[0], row[1]);
        } else {
            ssh_key tmp_key;
            if (ssh_pki_import_pubkey_base64(row[1] + strlen(rsa), SSH_KEYTYPE_RSA, &tmp_key) != SSH_OK) {
                fprintf(stderr, "Error importing public key for user %s : %s\n", row[0], row[1]);
            } else if (!ssh_key_cmp(pubkey, tmp_key, SSH_KEY_CMP_PUBLIC)) {
                size_t len = strlen(row[0]);
                char * username = malloc(len+1);
                strcpy(username, row[0]);
                ssh_key_free(tmp_key);
                mysql_free_result(result);
                return username;
            } else {
                ssh_key_free(tmp_key);
            }
        }
    }

    fprintf(stderr, "ERROR: Didn't find public key in database.\n");
    mysql_free_result(result);
    return NULL;
}

struct db_host_info * // returns NULL if no key found, this char * is to be freed from the calling code
db_get_host_info(const char * hostname)
{
    char buff[255];
    sprintf(buff, "SELECT priv_key, url, host_key FROM ssh_keys, hosts WHERE ssh_keys.id = hosts.ssh_key_id and hosts.name = \"%s\"", hostname);
    int res = mysql_query(db, buff);
    if (res != 0) {
        fprintf(stderr, "WARNING: Couldn't query db for server infos for host %s\n", hostname);
        return NULL;
    }
    MYSQL_RES *result = mysql_store_result(db);
    if (result == NULL) {
        fprintf(stderr, "FATAL: Couldn't retrieve server infos for %s from database.\n", hostname);
        return NULL;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row == NULL) {
        fprintf(stderr, "FATAL: Couldn't retrieve server db results for %s from database.\n", hostname);
        mysql_free_result(result);
        return NULL;
    }

    struct db_host_info * info = malloc(sizeof(struct db_host_info));
    memset(info, 0, sizeof(struct db_host_info));

    size_t len = strlen(row[0]);
    info->privkeytxt = malloc(len+1);
    strcpy(info->privkeytxt, row[0]);

    if (strncmp(row[1], "ssh://", 6) != 0) {
        fprintf(stderr, "FATAL: invalid host url %s\n", row[1]);
        return NULL;
    }
    size_t at_pos = 0;
    char done = 0;
    for(size_t i = 6; !done; ++i) {
        switch(*(row[1]+i)) {
          case '@':
            info->username = malloc(i-6+1);
            strncpy(info->username, row[1]+6, i-6);
            info->username[i-6] = '\0';
            at_pos = i;
            break;
          case '\0':
            info->address = malloc(i-at_pos);
            strncpy(info->address, row[1]+at_pos+1, i-at_pos-1);
            info->address[i-at_pos-1] = '\0';
            done = 1;
            break;
        }
        if (i > MAX_HOSTNAME_LENGTH + MAX_USERNAME_LENGTH + 6 + 1) {
            fprintf(stderr, "FATAL: Couldn't parse host url for host %s, too long.\n", hostname);
            if (info->username != NULL)
                free(info->username);
            return NULL;
        }
    }

    len = strlen(row[2]);
    info->hostkeyhash = malloc(len+1);
    strcpy(info->hostkeyhash, row[2]);

    mysql_free_result(result);
    return info;
}

void db_set_host_publickey_hash(const char * hostname, const char * hash)
{
    char buff[255];
    sprintf(buff, "UPDATE ssh_keys, hosts SET host_key = \"%s\" WHERE ssh_keys.id = hosts.ssh_key_id and hosts.name = \"%s\"", hash, hostname);
    int res = mysql_query(db, buff);
    if (res != 0) {
        fprintf(stderr, "WARNING: Couldn't set host key for host %s: %s\n", hostname, hash);
        return;
    }
    res = mysql_commit(db);
    if (res != 0) {
        fprintf(stderr, "WARNING: Couldn't commit after setting host key for host %s: %s\n", hostname, hash);
    }
}

void db_free_host_info(struct db_host_info * info)
{
    free(info->privkeytxt);
    free(info->address);
    free(info->username);
    free(info->hostkeyhash);
    free(info);
}
