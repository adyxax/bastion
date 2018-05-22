#ifndef _SESSION_H_
#define _SESSION_H_

#include <libssh/libssh.h>

#include "util.h"

void handle_session(ssh_event event, ssh_session session);

#endif
