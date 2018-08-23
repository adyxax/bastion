#include <libssh/callbacks.h>
#include <stdio.h>
#include <stdlib.h>

#include "client.h"
#include "proxy.h"

// callback function for channel data and exceptions
static int proxy_data_function(ssh_session session, ssh_channel channel, void *data,
                         uint32_t len, int is_stderr, void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;
    (void) session;
    (void) channel;
    (void) is_stderr;

    if (ssh_channel_is_open(pdata->client_channel))
        return ssh_channel_write(pdata->client_channel, (char*) data, len);
    else
        return SSH_ERROR;
}

// callback function for SSH channel PTY request from a client
static int proxy_pty_request(ssh_session session, ssh_channel channel,
                const char *term, int cols, int rows, int py, int px,
                void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *)userdata;

    (void) session;
    (void) channel;
    (void) py;
    (void) px;

    if (ssh_channel_is_open(pdata->client_channel)) {
        if (ssh_channel_request_pty_size(pdata->client_channel, term, cols, rows) == SSH_OK)
            return SSH_OK;
        else
            fprintf(stderr, "pty request failed\n");
    } else {
        fprintf(stderr, "pty request while client_channel not opened\n");
    }
    return SSH_ERROR;
}

// callback function for SSH channel PTY resize from a client
static int proxy_pty_resize(ssh_session session, ssh_channel channel, int cols,
               int rows, int py, int px, void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *)userdata;

    (void) session;
    (void) channel;
    (void) py;
    (void) px;

    if (ssh_channel_is_open(pdata->client_channel)) {
        if (ssh_channel_change_pty_size(pdata->client_channel, cols, rows) == SSH_OK)
            return SSH_OK;
        else
            fprintf(stderr, "pty resize failed\n");
    } else {
        fprintf(stderr, "pty resize while client_channel not opened\n");
    }
    return SSH_ERROR;
}

static int proxy_exec_request(ssh_session session, ssh_channel channel,
                        const char *command, void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;

    (void) session;
    (void) channel;

    if (ssh_channel_is_open(pdata->client_channel)) {
        if (ssh_channel_request_exec(pdata->client_channel, command) == SSH_OK)
            return SSH_OK;
        else
            printf("exec request failed\n");
    } else {
        fprintf(stderr, "exec request while client_channel not opened\n");
    }
    return SSH_ERROR;
}

static int proxy_shell_request(ssh_session session, ssh_channel channel,
                         void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;

    (void) session;
    (void) channel;

    if (ssh_channel_is_open(pdata->client_channel)) {
        if (ssh_channel_request_shell(pdata->client_channel) == SSH_OK)
            return SSH_OK;
        else
            fprintf(stderr, "shell request failed\n");
    } else {
        fprintf(stderr, "shell request while client channel not opened\n");
    }
    return SSH_ERROR;
}

static int proxy_subsystem_request(ssh_session session, ssh_channel channel,
                             const char *subsystem, void *userdata) {
    (void) session;
    (void) channel;
    (void) subsystem;
    (void) userdata;
    return SSH_ERROR; // TODO ssh subsystem request
    //if (ssh_channel_is_open(pdata->client_channel)) {
    //}
}

static void proxy_channel_eof_callback (ssh_session session, ssh_channel channel, void *userdata)
{
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;
    (void) session;
    (void) channel;
    if (ssh_channel_is_open(pdata->client_channel))
        ssh_channel_send_eof(pdata->client_channel);
}

static void proxy_channel_close_callback (ssh_session session, ssh_channel channel, void *userdata)
{
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;
    (void) session;
    (void) channel;
    if (ssh_channel_is_open(pdata->client_channel))
        ssh_channel_close(pdata->client_channel);
}

static void proxy_channel_exit_status_callback (ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
    (void) session;
    (void) channel;
    (void) exit_status;
    (void) userdata;
    printf("proxy exit status callback\n");
}

static void proxy_channel_signal_callback (ssh_session session, ssh_channel channel,
                                    const char *signal, void *userdata) {
    (void) session;
    (void) channel;
    (void) signal;
    (void) userdata;
    printf("proxy signal callback\n");
}

static void proxy_channel_exit_signal_callback (ssh_session session, ssh_channel channel,
                                    const char *signal, int core, const char *errmsg,
                                    const char *lang, void *userdata) {
    (void) session;
    (void) channel;
    (void) signal;
    (void) core;
    (void) errmsg;
    (void) lang;
    (void) userdata;
    printf("proxy exit signal callback\n");
}

void handle_proxy_session(ssh_event event, ssh_session session, ssh_channel my_channel, const char * hostname)
{
    struct client_channel_data_struct * cdata;

    struct proxy_channel_data_struct pdata = {
        .event = event,
        .my_session = session,
        .my_channel = my_channel,
        .client_channel = NULL,
    };

    cdata = client_dial(event, &pdata, hostname);

    if (cdata == NULL) {
        return;
    }
    pdata.client_channel = cdata->my_channel;

    /* We tie everything together */
    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &pdata,
        .channel_data_function = proxy_data_function,
        .channel_eof_function = proxy_channel_eof_callback,
        .channel_close_function = proxy_channel_close_callback,
        .channel_signal_function = proxy_channel_signal_callback,
        .channel_exit_status_function = proxy_channel_exit_status_callback,
        .channel_exit_signal_function = proxy_channel_exit_signal_callback,
        .channel_pty_request_function = proxy_pty_request,
        .channel_shell_request_function = proxy_shell_request,
        .channel_pty_window_change_function = proxy_pty_resize,
        .channel_exec_request_function = proxy_exec_request,
        .channel_subsystem_request_function = proxy_subsystem_request,
        .channel_auth_agent_req_function = NULL,
        .channel_x11_req_function = NULL,
        .channel_env_request_function = NULL,
        .channel_write_wontblock_function = NULL,
    };
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(my_channel, &channel_cb);

    do {
        /* Poll the main event which takes care of the sessions and channels */
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
            break;
        }
    } while(ssh_channel_is_open(my_channel) && ssh_channel_is_open(pdata.client_channel));
    if (ssh_channel_is_open(my_channel))
        ssh_channel_close(my_channel);
    if (ssh_channel_is_open(cdata->my_channel))
        ssh_channel_close(cdata->my_channel);

    client_cleanup(cdata);
}
