#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common/config.h"
#include "state.h"

struct state {
    unsigned long long session_id;
    char * destination;
    char * bastion_username;
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
state_set_bastion_username(const char * name)
{
    if (state.bastion_username != NULL) {
        fprintf(stderr, "BUG found, attempting to overwrite state.bastion_username that has already been set\n");
        return 1;
    }
    size_t len = strnlen(name, MAX_USERNAME_LENGTH + 1);
    if (len >= MAX_USERNAME_LENGTH + 1) {
        fprintf(stderr, "Username too long, max length is %d.\n", MAX_USERNAME_LENGTH);
        return 1;
    }
    state.bastion_username = malloc(len+1);
    strncpy(state.bastion_username, name, len+1);
    return 0;
}

const char * state_get_bastion_username(void)
{
    return state.bastion_username;
}

char // return 0 if ok, greater than 0 otherwise
state_set_session_id(const unsigned long long id)
{
    if (state.session_id != 0) {
        fprintf(stderr, "BUG found, attempting to set a state.session_id that has already been set\n");
        return 1;
    }
    state.session_id = id;
    return 0;
}

unsigned long long state_get_session_id(void)
{
    return state.session_id;
}

void state_clean(void)
{
    free(state.destination);
    state.destination = NULL;
}
