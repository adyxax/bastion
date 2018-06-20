#ifndef SESSION_H_
#define SESSION_H_

#include <libssh/libssh.h>

#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)

/* A userdata struct for session. */
struct session_data_struct {
    /* Pointer to the channel the session will allocate. */
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
    // ssh user name when login
    char * login_username;
};

void handle_session(ssh_event event, ssh_session session);

#endif
