#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "../config.h"
#include "session.h"

/* SIGCHLD handler for cleaning up dead children. */
static void sigchld_handler(int signo) {
    (void) signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* SIGINT handler for cleaning up on forced exit. */
static ssh_bind sshbind;
static ssh_session session;

__attribute__((noreturn)) void sigint_handler(int signo)
{
    (void) signo;
    ssh_free(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    exit(0);
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
    // Set up SIGINT handler
    struct sigaction sa2;
    sa2.sa_handler = sigint_handler;
    sigemptyset(&sa2.sa_mask);
    sa2.sa_flags = 0;
    if (sigaction(SIGINT, &sa2, NULL) != 0) {
        fprintf(stderr, "Failed to register SIGINT handler\n");
        return 1;
    }

    // Initializing ssh context
    ssh_init();

    // Initializing ssh_bind
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Error initializing ssh_bind\n");
        exit(-1);
    }
    int port = 2222;
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, DSAKEY_PATH);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, RSAKEY_PATH);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, ECDSAKEY_PATH);

    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        ssh_finalize();
        return 1;
    }

    while (1) {
        session = ssh_new();
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
                /* Remove socket binding, which allows us to restart the parent process, without terminating existing sessions. */
                ssh_bind_free(sshbind);

                ssh_event event = ssh_event_new();
                if (event != NULL) {
                    /* Blocks until the SSH session ends */
                    handle_session(event, session);
                    ssh_event_free(event);
                } else {
                    fprintf(stderr, "Could not create polling context\n");
                }
                ssh_disconnect(session);
                ssh_free(session);
                ssh_finalize();

                return 0;
              case -1:
                fprintf(stderr, "Failed to fork\n");
            }
        } else {
            fprintf(stderr, "Error accepting a connection : %s\n", ssh_get_error(sshbind));
            ssh_disconnect(session);
            ssh_free(session);
            ssh_bind_free(sshbind);
            ssh_finalize();
            return 1;
        }
        /* Since the session has been passed to a child fork, do some cleaning up at the parent process. */
        ssh_disconnect(session);
        ssh_free(session);
    }
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
