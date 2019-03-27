#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "common/config.h"
#include "session.h"
#include "state.h"

/* SIGCHLD handler for cleaning up dead children. */
static void sigchld_handler(int signo) {
    (void) signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* SIGINT handler for cleaning up on forced exit. */
static ssh_bind sshbind = NULL;
static ssh_session session = NULL;

__attribute__((noreturn)) static void sigint_handler(int signo)
{
    (void) signo;
    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
    state_clean();
    config_clean();
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
        return 2;
    }

    // Initializing ssh context
    if (ssh_init() != 0) {
        fprintf(stderr, "Failed to initialize libssh global cryptographic data structures.\n");
        return 3;
    };

    // Initializing configuration context
    if (config_load() != 0) {
        fprintf(stderr, "Failed to load configuration file %s.\n", CONFIG_PATH);
        config_clean();
        ssh_finalize();
        return 4;
    }

    // Initializing ssh_bind
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Error initializing ssh_bind\n");
        config_clean();
        ssh_finalize();
        return 5;
    }
    int listen_port = config_get_port();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &listen_port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, config_get_key_dsa());
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, config_get_key_rsa());
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, config_get_key_ecdsa());

    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        config_clean();
        ssh_finalize();
        return 6;
    }

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Error initializing ssh_session\n");
            break;
        }
#ifdef LIBSSH_VERBOSE_OUTPUT
        int verbosity = SSH_LOG_PROTOCOL;
        ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
#endif

        // Blocks until there is a new incoming connection
        if (ssh_bind_accept(sshbind,session) == SSH_OK){
            switch(fork()) {
              case 0:
                /* Remove the SIGCHLD handler inherited from parent. */
                sa.sa_handler = SIG_DFL;
                sigaction(SIGCHLD, &sa, NULL);
                /* Remove socket binding, which allows us to restart the parent process, without terminating existing sessions. */
                ssh_bind_free(sshbind);
                sshbind = NULL;

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
                config_clean();
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
            config_clean();
            ssh_finalize();
            return 7;
        }
        /* Since the session has been passed to a child fork, do some cleaning up at the parent process. */
        ssh_disconnect(session);
        ssh_free(session);
    }
    ssh_bind_free(sshbind);
    config_clean();
    ssh_finalize();
    return 0;
}
