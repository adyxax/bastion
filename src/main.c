#include <libssh/callbacks.h>
#include <libssh/server.h>
//#include <fcntl.h>
//#include <libutil.h>
//#include <poll.h>
//#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
//#include <sys/ioctl.h>
#include <sys/wait.h>
//#include <util.h>

#include "session.h"

/* SIGCHLD handler for cleaning up dead children. */
static void sigchld_handler(int signo) {
    (void) signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main()
{
    // Set up SIGCHLD handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        fprintf(stderr, "Failed to register SIGCHLD handler\n");
        return 1;
    }

    // Initializing ssh context
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();

    // Initializing ssh_bind
    ssh_bind sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Error initializing ssh_bind\n");
        exit(-1);
    }
    int port = 2222;
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, "ssh_host_ecdsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    while (1) {
        ssh_session session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Error initializing ssh_session\n");
            break;
        }
        int verbosity = SSH_LOG_PROTOCOL;
        ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

        // Blocks until there is a new incoming connection
        if (ssh_bind_accept(sshbind,session) == SSH_OK){
            switch(fork()) {
              case 0:
                /* Remove the SIGCHLD handler inherited from parent. */
                sa.sa_handler = SIG_DFL;
                sigaction(SIGCHLD, &sa, NULL);
                /* Remove socket binding, which allows us to restart the
                 * parent process, without terminating existing sessions. */
                ssh_bind_free(sshbind);

                ssh_event event = ssh_event_new();
                if (event != NULL) {
                    /* Blocks until the SSH session ends by either
                     * child process exiting, or client disconnecting. */
                    handle_session(event, session);
                    ssh_event_free(event);
                } else {
                    fprintf(stderr, "Could not create polling context\n");
                }
                ssh_disconnect(session);
                ssh_free(session);

                exit(0);
              case -1:
                fprintf(stderr, "Failed to fork\n");
            }
        } else {
            fprintf(stderr, "Error accepting a connection : %s\n", ssh_get_error(sshbind));
            exit(1);
        }
        /* Since the session has been passed to a child fork, do some cleaning
         * up at the parent process. */
        ssh_disconnect(session);
        ssh_free(session);
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
