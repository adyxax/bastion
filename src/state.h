#ifndef STATE_H_
#define STATE_H_

char state_set_ssh_destination(const char * dest);
const char * state_get_ssh_destination(void);
char state_set_bastion_username(const char * name);
const char * state_get_bastion_username(void);
char state_set_session_id(const unsigned long long id);
unsigned long long state_get_session_id(void);
void state_clean(void);

#endif
