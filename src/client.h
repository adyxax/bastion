#ifndef CLIENT_H_
#define CLIENT_H_

#include <libssh/libssh.h>

#include "proxy.h"
#include "session.h"

/* A userdata struct for channel. */
struct client_channel_data_struct {
    /* Event which is used to poll */
    ssh_event event;
    ssh_session my_session;
    ssh_channel my_channel;
    ssh_channel proxy_channel;
    struct ssh_channel_callbacks_struct * client_channel_cb;
};

struct client_channel_data_struct* client_dial(ssh_event event, struct proxy_channel_data_struct *pdata);
void client_cleanup(struct client_channel_data_struct *cdata);

#endif
