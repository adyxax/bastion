#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../config.h"
#include "state.h"

struct state {
    char * destination;
    char * username;
    int session_id;
    int padding;
};

static struct state state = {0};

char // returns 0 if ok, greater than 0 otherwise
state_set_ssh_destination(const char * name)
{
    if (state.destination != NULL) {
        fprintf(stderr, "BUG found, attempting to overwrite state.destination that has already been set\n");
        return 1;
    }
    size_t len = strnlen(name, MAX_HOSTNAME_LENGTH + 1);
    if (len >= MAX_HOSTNAME_LENGTH + 1) {
        fprintf(stderr, "Hostname too long, max length is %d.\n", MAX_HOSTNAME_LENGTH);
        return 2;
    }
    state.destination = malloc(len+1);
    strncpy(state.destination, name, len+1);
    return 0;
}

const char * state_get_ssh_destination(void)
{
    return state.destination;
}

char // return 0 if ok, greater than 0 otherwise
state_set_username(const char * name)
{
    if (state.username != NULL) {
        fprintf(stderr, "BUG found, attempting to overwrite state.username that has already been set\n");
        return 1;
    }
    size_t len = strnlen(name, MAX_USERNAME_LENGTH + 1);
    if (len >= MAX_USERNAME_LENGTH + 1) {
        fprintf(stderr, "Username too long, max length is %d.\n", MAX_USERNAME_LENGTH);
        return 1;
    }
    state.username = malloc(len+1);
    strncpy(state.username, name, len+1);
    return 0;
}

const char * state_get_username(void)
{
    return state.username;
}

char // return 0 if ok, greater than 0 otherwise
state_set_session_id(const int id)
{
    if (state.session_id != 0) {
        fprintf(stderr, "BUG found, attempting to overwrite state.username that has already been set\n");
        return 1;
    }
    state.session_id = id;
    return 0;
}

int state_get_session_id(void)
{
    return state.session_id;
}

void state_clean(void)
{
    free(state.destination);
    state.destination = NULL;
    free(state.username);
    state.username = NULL;
}
