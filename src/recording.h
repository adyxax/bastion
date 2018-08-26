#include "../config.h"

#ifdef SESSION_RECORDING
#ifndef RECORDING_H_
#define RECORDING_H_

void clean_recorder(void);
char init_recorder(void);
char record(void* data, size_t len);

#endif
#endif
