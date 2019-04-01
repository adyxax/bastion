#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <parg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "common/config.h"
#include "session.h"
#include "state.h"

static void usage(char **argv)
{
    printf("Usage: %s [-h] [-v] [-t] [-f] [-c STRING]\n", argv[0]);
    printf("  -h : show this help message and exit\n");
    printf("  -v : show version and exit\n");
    printf("  -t : test configuration file and exit\n");
    printf("  -f : stay in foreground (don't fork)\n");
    printf("  -c : specify a path to a configuration file to use instead of the default %s\n", CONFIG_PATH);
}

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

int main(int argc, char **argv)
{
    // Set up SIGINT handler
    struct sigaction sa2;
    sa2.sa_handler = sigint_handler;
    sigemptyset(&sa2.sa_mask);
    sa2.sa_flags = 0;
    if (sigaction(SIGINT, &sa2, NULL) != 0) {
        fprintf(stderr, "Failed to register SIGINT handler\n");
        return 1;
    }

    // Argument parsing
    struct parg_state ps;
    int c;
    char test_only = 0, dont_fork = 0;
    const char *config_file = CONFIG_PATH;
    parg_init(&ps);
    //while ((int c = parg_getopt(&ps, argc, argv, "hs:v")) != -1) {
    while ((c = parg_getopt(&ps, argc, argv, "hvtfc:")) != -1) {
        switch (c) {
          case 1:
            printf("invalid non option '%s'\n", ps.optarg);
            return 2;
          case 'h':
            usage(argv);
            return 0;
          case 'v':
            printf("%s %s - %s\n", argv[0], VERSION, GIT_HASH);
            return 0;
          case 't':
            test_only = 1;
            break;
          case 'f':
            dont_fork = 1;
            break;
          case 'c':
            config_file = ps.optarg;
            break;
          case '?':
            if (ps.optopt == 'c') {
                printf("option -c requires the path to a configuration in argument.\n");
            }
            else {
                printf("unknown option -%c\n", ps.optopt);
            }
            usage(argv);
            return 3;
          default:
            printf("error: unhandled option -%c\n", c);
            return 4;
            break;
        }
    }

    if (test_only) {
        if (config_load(config_file) != 0) {
            fprintf(stderr, "Failed to load configuration file %s.\n", CONFIG_PATH);
            config_clean();
            return 5;
        }
        config_clean();
        return 0;
    }

    struct sigaction sa;
    if (!dont_fork) {
        // Set up SIGCHLD handler
        sa.sa_handler = sigchld_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        if (sigaction(SIGCHLD, &sa, NULL) != 0) {
            fprintf(stderr, "Failed to register SIGCHLD handler\n");
            return 6;
        }
    }

    // Initializing ssh context
    if (ssh_init() != 0) {
        fprintf(stderr, "Failed to initialize libssh global cryptographic data structures.\n");
        return 7;
    };

    // Initializing configuration context
    if (config_load(config_file) != 0) {
        fprintf(stderr, "Failed to load configuration file %s.\n", CONFIG_PATH);
        config_clean();
        ssh_finalize();
        return 8;
    }

    // Initializing ssh_bind
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Error initializing ssh_bind\n");
        config_clean();
        ssh_finalize();
        return 9;
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
        return 10;
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
            int res = 0;
            if (!dont_fork) {
                res = fork();
            }

            switch(res) {
              case 0:
                if (!dont_fork) {
                    /* Remove the SIGCHLD handler inherited from parent. */
                    sa.sa_handler = SIG_DFL;
                    sigaction(SIGCHLD, &sa, NULL);
                }
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
            return 10;
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
