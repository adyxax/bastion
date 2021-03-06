#include <libssh/callbacks.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/config.h"
#include "common/data.h"
#include "client.h"
#ifdef SESSION_RECORDING
#include "recording.h"
#endif
#include "state.h"

// callback function for channel data and exceptions
static int client_data_function(ssh_session session, ssh_channel channel, void *data,
                         uint32_t len, int is_stderr, void *userdata) {
    struct client_channel_data_struct *cdata = (struct client_channel_data_struct *) userdata;
    (void) session;
    (void) channel;
    (void) is_stderr;

    if (ssh_channel_is_open(cdata->proxy_channel)) {
#ifdef SESSION_RECORDING
        record(data, len);
#endif
        return ssh_channel_write(cdata->proxy_channel, (char*) data, len);
    } else
        return SSH_ERROR;
}

static void client_channel_eof_callback (ssh_session session, ssh_channel channel, void *userdata)
{
    struct client_channel_data_struct *cdata = (struct client_channel_data_struct *) userdata;
    (void) session;
    (void) channel;

    if (ssh_channel_is_open(cdata->proxy_channel))
        ssh_channel_send_eof(cdata->proxy_channel);
}

static void client_channel_close_callback (ssh_session session, ssh_channel channel, void *userdata)
{
    struct client_channel_data_struct *cdata = (struct client_channel_data_struct *) userdata;
    (void) session;
    (void) channel;

    if (ssh_channel_is_open(cdata->proxy_channel))
        ssh_channel_close(cdata->proxy_channel);
}

static void client_channel_exit_status_callback (ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
    (void) session;
    (void) channel;
    (void) userdata;
    printf("client exit status callback %d\n", exit_status);
}

static void client_channel_signal_callback (ssh_session session, ssh_channel channel,
                                    const char *signal, void *userdata) {
    (void) session;
    (void) channel;
    (void) signal;
    (void) userdata;
    printf("client signal callback\n");
}

static void client_channel_exit_signal_callback (ssh_session session, ssh_channel channel,
                                    const char *signal, int core, const char *errmsg,
                                    const char *lang, void *userdata) {
    (void) session;
    (void) channel;
    (void) signal;
    (void) core;
    (void) errmsg;
    (void) lang;
    (void) userdata;
    printf("client exit signal callback\n");
}

struct client_channel_data_struct* client_dial(ssh_event event, struct proxy_channel_data_struct *pdata)
{
    const char * hostname = state_get_ssh_destination();
    struct client_channel_data_struct *cdata = malloc(sizeof(*cdata));
    cdata->event = event;
    cdata->my_session = NULL;
    cdata->my_channel = NULL;
    cdata->proxy_channel = pdata->my_channel;
    cdata->client_channel_cb = NULL;

    /* First we try to add the private key that the server will accept */
    struct data_host_info * info = data_get_host_info(hostname);
    if (info == NULL)
        goto host_info_clean;

    /* We try to connect to the remote server */
    printf("Connecting to %s\n", hostname);
    cdata->my_session = ssh_new();

    ssh_options_set(cdata->my_session, SSH_OPTIONS_HOST, info->address);
    ssh_options_set(cdata->my_session, SSH_OPTIONS_USER, info->username);
#ifdef LIBSSH_VERBOSE_OUTPUT
    int verbosity = SSH_LOG_PROTOCOL;
    ssh_options_set(cdata->my_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
#endif

    if (ssh_connect(cdata->my_session) != SSH_OK) {
        printf("Error connecting to %s: %s\n", hostname, ssh_get_error(cdata->my_session));
        goto session_clean;
    }

    /* We now validate the remote server's public key */
    ssh_key server_pub_key = NULL;
    if (ssh_get_server_publickey(cdata->my_session, &server_pub_key) != SSH_OK) {
        fprintf(stderr, "Error getting server publickey: %s\n", ssh_get_error(cdata->my_session));
        goto pubkey_clean;
    }
    char *pubkeystr = NULL;
    if (ssh_pki_export_pubkey_base64(server_pub_key, &pubkeystr) != SSH_OK) {
        fprintf(stderr, "Got invalid public key from server attempt, this shouldn't happen.\n");
        goto pubkey_clean;
    }
    if (strcmp(info->pubkey, pubkeystr) != 0) {
        fprintf(stderr, "Error : public key of server %s doesn't match.\n", hostname);
        fprintf(stderr, "got : %s\n", pubkeystr);
        fprintf(stderr, "exp : %s\n", info->pubkey);
        goto pubkey_clean;
    }
    free(pubkeystr);
    ssh_key_free(server_pub_key);

    /* With the server checked, we can authenticate */
    if(ssh_userauth_publickey(cdata->my_session, NULL, info->key) == SSH_AUTH_SUCCESS){
        printf("Authentication success\n");
    } else {
        printf("Error private key was rejected\n");
        goto session_clean;
    }

    /* we open the client channel */
    cdata->my_channel = ssh_channel_new(cdata->my_session);
    if (cdata->my_channel == NULL) {
        printf("Couldn't open client channel to %s\n", hostname);
        goto channel_clean;
    }

    /* we open a session channel for the future shell, not suitable for tcp
     * forwarding */
    if (ssh_channel_open_session(cdata->my_channel) != SSH_OK) {
        printf("Couldn't open the session channel\n");
        goto channel_clean;
    }

    cdata->client_channel_cb = malloc(sizeof(*cdata->client_channel_cb));
    memset(cdata->client_channel_cb, 0, sizeof(*cdata->client_channel_cb));
    cdata->client_channel_cb->userdata = cdata;
    cdata->client_channel_cb->channel_data_function = client_data_function;
    cdata->client_channel_cb->channel_eof_function = client_channel_eof_callback;
    cdata->client_channel_cb->channel_close_function = client_channel_close_callback;
    cdata->client_channel_cb->channel_exit_status_function = client_channel_exit_status_callback;
    cdata->client_channel_cb->channel_signal_function = client_channel_signal_callback;
    cdata->client_channel_cb->channel_exit_signal_function = client_channel_exit_signal_callback;

    ssh_callbacks_init(cdata->client_channel_cb);
    ssh_set_channel_callbacks(cdata->my_channel, cdata->client_channel_cb);
    ssh_event_add_session(event, cdata->my_session);

    // TODO only start recording upong shell_exec or pty_request in proxy.c.
    // It will be important when we start supporting scp
#ifdef SESSION_RECORDING
    if (init_recorder() != 0) {
        goto channel_clean;
    }
#endif

    free(info);
    return cdata;

channel_clean:
    ssh_channel_free(cdata->my_channel);
    goto session_clean;
pubkey_clean:
    free(pubkeystr);
    ssh_key_free(server_pub_key);
session_clean:
    ssh_disconnect(cdata->my_session);
    ssh_free(cdata->my_session);
    free(info);
host_info_clean:
    free(cdata);
    return NULL;
}

void client_cleanup(struct client_channel_data_struct *cdata)
{
#ifdef SESSION_RECORDING
    clean_recorder();
#endif
    ssh_event_remove_session(cdata->event, cdata->my_session);
    ssh_channel_free(cdata->my_channel);
    ssh_disconnect(cdata->my_session);
    ssh_free(cdata->my_session);
    free(cdata->client_channel_cb);
    free(cdata);
}
