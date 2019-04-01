#include <libconfig.h>
#include <stdlib.h>

#include "config.h"
#include "data_for_config.h"

config_t * config = NULL;

char // returns 0 if ok, greater than 0 otherwise
config_load(const char *config_file)
{
    config = malloc(sizeof(config_t));
    config_init(config);
    config_set_tab_width(config, 4);
    if (config_read_file(config, config_file) != CONFIG_TRUE) {
        switch(config_error_type(config)) {
          case CONFIG_ERR_NONE:
            fprintf(stderr, "Configuration read error with none type reported... This shouldn't happen!\n");
            break;
          case CONFIG_ERR_FILE_IO:
            fprintf(stderr, "Configuration I/O error, the most common cause is a file not found at %s\n", CONFIG_PATH);
            break;
          case CONFIG_ERR_PARSE:
            fprintf(stderr, "Configuration parse error\n");
            break;
        }
        fprintf(stderr, "Configuration read error occured at %s:%d %s\n", config_error_file(config), config_error_line(config), config_error_text(config));
        return 1;
    }
    return data_init(config);
}

int config_get_port(void)
{
    int port;
    if (config_lookup_int(config, "port", &port) != CONFIG_TRUE) {
        return DEFAULT_PORT;
    }
    return port;
}

const char * config_get_key_dsa(void)
{
    const char * key;
    if (config_lookup_string(config, "keys.dsa", &key) != CONFIG_TRUE) {
        return DEFAULT_DSAKEY_PATH;
    }
    return key;
}

const char * config_get_key_rsa(void)
{
    const char * key;
    if (config_lookup_string(config, "keys.rsa", &key) != CONFIG_TRUE) {
        return DEFAULT_RSAKEY_PATH;
    }
    return key;
}

const char * config_get_key_ecdsa(void)
{
    const char * key;
    if (config_lookup_string(config, "keys.ecdsa", &key) != CONFIG_TRUE) {
        return DEFAULT_ECDSAKEY_PATH;
    }
    return key;
}

#ifdef SESSION_RECORDING
const char * config_get_session_recording_path(void)
{
    const char * key;
    if (config_lookup_string(config, "session_recording.path", &key) != CONFIG_TRUE) {
        return DEFAULT_SESSION_RECORDING_PATH;
    }
    return key;
}
#endif

void config_clean(void)
{
    if (config != NULL) {
        data_clean();
        config_destroy(config);
        free(config);
        config = NULL;
    }
}
