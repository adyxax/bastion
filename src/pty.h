#ifndef _PTY_H_
#define _PTY_H_

#include "util.h"

int pty_request(ssh_session session, ssh_channel channel,
                const char *term, int cols, int rows, int py, int px,
                void *userdata);
int pty_resize(ssh_session session, ssh_channel channel, int cols,
               int rows, int py, int px, void *userdata);
int exec_pty(const char *mode, const char *command,
             struct channel_data_struct *cdata);
int exec_nopty(const char *command, struct channel_data_struct *cdata);

#endif
