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

    printf("pty request\n");
    int rc = ssh_channel_request_pty_size(pdata->client_channel, term, cols, rows);
    if (rc == SSH_OK) {
        printf("pty request successfull\n");
    } else {
        printf("pty request failed\n");
    }
    return rc;
}

// callback function for SSH channel PTY resize from a client
static int proxy_pty_resize(ssh_session session, ssh_channel channel, int cols,
               int rows, int py, int px, void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *)userdata;

    (void) session;
    (void) channel;
    (void) py;
    (void) px;

    if (pdata->client_channel == NULL || ssh_channel_is_open(pdata->client_channel) == 0) {
        fprintf(stderr, "proxy pty oups!!!!!\n");
        return SSH_ERROR;
    }
    printf("pty resize\n");
    int rc = ssh_channel_change_pty_size(pdata->client_channel, cols, rows);
    if (rc == SSH_OK) {
        printf("pty resize successfull\n");
    } else {
        printf("pty resize failed\n");
    }
    return rc;
}

static int proxy_exec_request(ssh_session session, ssh_channel channel,
                        const char *command, void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;

    (void) session;
    (void) channel;

    printf("exec request : %s\n", command); // TODO
    int rc = ssh_channel_request_exec(pdata->client_channel, command);
    if (rc == SSH_OK) {
        printf("exec request successfull\n");
    } else {
        printf("exec request failed\n");
    }
    return rc;
}

static int proxy_shell_request(ssh_session session, ssh_channel channel,
                         void *userdata) {
    struct proxy_channel_data_struct *pdata = (struct proxy_channel_data_struct *) userdata;

    (void) session;
    (void) channel;

    printf("shell request\n");
    int rc = ssh_channel_request_shell(pdata->client_channel);
    if (rc == SSH_OK) {
        printf("shell request successfull\n");
    } else {
        printf("shell request failed\n");
    }
    return rc;
}

static int proxy_subsystem_request(ssh_session session, ssh_channel channel,
                             const char *subsystem, void *userdata) {
    ///* subsystem requests behave simillarly to exec requests. */
    //if (strcmp(subsystem, "sftp") == 0) {
    //    printf("sftp request\n"); // TODO
    //    return exec_request(session, channel, SFTP_SERVER_PATH, userdata);
    //}
    (void) session;
    (void) channel;
    (void) subsystem;
    (void) userdata;
    return SSH_ERROR; // TODO
}

static void proxy_channel_eof_callback (ssh_session session, ssh_channel channel, void *userdata)
{
    (void) session;
    (void) channel;
    (void) userdata;
    printf("proxy eof callback\n");
}

static void proxy_channel_close_callback (ssh_session session, ssh_channel channel, void *userdata)
{
    (void) session;
    (void) channel;
    (void) userdata;
    printf("proxy close callback\n");
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

    //ssh_event_remove_session(event, session);
    cdata = client_dial(event, &pdata, hostname);
    //for (int n = 0; n < 10; n++) {
    //    ssh_event_dopoll(event, 100);
    //}
    //ssh_event_add_session(event, session);

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
  /** This function will be called when a client requests agent
   * authentication forwarding.
   */
  //ssh_channel_auth_agent_req_callback channel_auth_agent_req_function;
  /** This function will be called when a client requests X11
   * forwarding.
   */
  //ssh_channel_x11_req_callback channel_x11_req_function;
  /** This function will be called when a client requests an environment
   * variable to be set.
   */
  /** This function will be called when the channel write is guaranteed
   * not to block.
   */
  //    .channel_write_wontblock_function = proxy_channel_write_wontblock,
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
