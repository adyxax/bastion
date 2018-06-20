#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "../config.h"
#include "proxy.h"
#include "session.h"

int auth_pubkey(ssh_session session, const char *user,
                       struct ssh_key_struct *pubkey,
                       char signature_state, void *userdata) {
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;

    // For some reason, libssh can call this twice for the same key
    if (sdata->authenticated == 1)
        return SSH_ERROR;

    if (signature_state != SSH_PUBLICKEY_STATE_NONE && signature_state != SSH_PUBLICKEY_STATE_VALID) {
        fprintf(stderr, "Invalid signature state\n");
        sdata->auth_attempts++;
        return SSH_AUTH_DENIED;
    }

    // TODO check for an invite

    ssh_key reference_key = ssh_key_new();
    ssh_pki_import_pubkey_base64(USER_RSA_PUBKEY, SSH_KEYTYPE_RSA, &reference_key); // TODO fetch all pubkeys from db
    if (!ssh_key_cmp(pubkey, reference_key, SSH_KEY_CMP_PUBLIC)) {
        sdata->authenticated = 1;
        ssh_key_free(reference_key);
        size_t len = strnlen(user, MAX_HOSTNAME_LENGTH + 1);
        if (len == MAX_HOSTNAME_LENGTH + 1) {
            fprintf(stderr, "Hostname too long, max length is %d.\n", MAX_HOSTNAME_LENGTH);
            return SSH_ERROR;
        }
        sdata->login_username = malloc(len+1);
        memset(sdata->login_username, 0, len+1);
        strncpy(sdata->login_username, user, len);
        return SSH_AUTH_SUCCESS;
    } else {
        ssh_key_free(reference_key);
        sdata->auth_attempts++;
        return SSH_AUTH_DENIED;
    }
}

ssh_channel channel_open(ssh_session session, void *userdata) {
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    if (sdata->channel == NULL) {
        sdata->channel = ssh_channel_new(session);
        return sdata->channel;
    } else {
        // Only one channel allowed
        return NULL;
    }
}

void handle_session(ssh_event event, ssh_session session) {
    /* Our struct holding information about the session. */
    struct session_data_struct sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0,
        .login_username = NULL
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_pubkey_function = auth_pubkey,
        .channel_open_request_session_function = channel_open,
    };
    ssh_callbacks_init(&server_cb);
    ssh_set_server_callbacks(session, &server_cb);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        return;
    }

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY);
    ssh_event_add_session(event, session);

    for (int n=0; sdata.authenticated == 0 || sdata.channel == NULL; n++) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 10 seconds (n * 100ms), disconnect. */
        if (sdata.auth_attempts >= 3) {
            fprintf(stderr, "Closing connection after 3 failed auth attempts\n");
            return;
        }
        if (n >= 100) {
            fprintf(stderr, "Closing connection after 10 seconds without successfull authentication\n");
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "%s\n", ssh_get_error(session));
            return;
        }
    }

    handle_proxy_session(event, session, sdata.channel, sdata.login_username);

    if (ssh_channel_is_open(sdata.channel)) {
        ssh_channel_close(sdata.channel);
    }

    /* Wait up to 5 seconds for the client to terminate the session. */
    for (int n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
        ssh_event_dopoll(event, 100);
    }
    free(sdata.login_username);
    ssh_event_remove_session(event, session);
}
