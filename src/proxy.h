#ifndef PROXY_H_
#define PROXY_H_

#include <libssh/libssh.h>

#include "session.h"

/* A userdata struct for channel. */
struct proxy_channel_data_struct {
    /* Event which is used to poll */
    ssh_event event;
    ssh_session my_session;
    ssh_channel my_channel;
    ssh_channel client_channel;
};
void handle_proxy_session(ssh_event event, ssh_session session, ssh_channel my_channel, const char * hostname);

#endif
