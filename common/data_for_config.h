#ifndef COMMON_DATA_FOR_CONFIG_H_
#define COMMON_DATA_FOR_CONFIG_H_

#include <libconfig.h>
#include "data.h"

char  // returns 0 if ok, something else otherwise
data_init(const config_t * config);

#endif
