#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <ttyrec.h>

#include "../config.h"
#include "recording.h"
#include "state.h"

#ifdef SESSION_RECORDING
static recorder recorder_handle = NULL;

void clean_recorder(void)
{
    ttyrec_w_close(recorder_handle);
    recorder_handle = NULL;
}

static char * // returns NULL if error, this char * is to be freed from the calling code
make_filename(void)
{
    char * format = LOG_FILENAME_FORMAT;
    char * filename = NULL;
    unsigned int fname_pos = 0;
    unsigned int format_pos = 0;

    filename = malloc(LOG_FILENAME_MAX_LEN+1);

    size_t format_len = strlen(format);
    while (format_pos < format_len + 1 && fname_pos < LOG_FILENAME_MAX_LEN +1) {
        if (format[format_pos] == '$') {
            format_pos++;
            if (format[format_pos] == 'd') {
                time_t t;
                struct tm * tm;
                time(&t);
                tm = localtime(&t);
                fname_pos += strftime(filename + fname_pos, LOG_FILENAME_MAX_LEN - fname_pos, "%F", tm);
            } else if (format[format_pos] == 'h') {
                const char * hostname = state_get_ssh_destination();
                size_t len = strlen(hostname);
                strcpy(filename + fname_pos, hostname);
                fname_pos += len;
            } else if (format[format_pos] == 'u') {
                const char * username = state_get_bastion_username();
                size_t len = strlen(username);
                strcpy(filename + fname_pos, username);
                fname_pos += len;
            } else if (format[format_pos] == 'i') {
                sprintf(filename + fname_pos, "%d", state_get_session_id());
                fname_pos += strlen(filename + fname_pos);
            }
            format_pos++;
        } else {
            filename[fname_pos] = format[format_pos];
            if (filename[fname_pos] == '/') { // We create the corresponding directory if it doesn't exist
                filename[fname_pos+1] = '\0';
                DIR* dir = opendir(filename);
                if (dir)
                    closedir(dir);
                else {
                    int ret = mkdir(filename, LOG_DIRECTORY_MODE);
                    if (ret != 0) {
                        fprintf(stderr, "Couldn't create log directory %s : %s\n", filename, strerror( errno ));
                    }
                }
            }
            format_pos++;
            fname_pos++;
        }
    }

    if (filename[fname_pos-1] != '\0') {
        fprintf(stderr, "Log file name is too long, check LOG_FILENAME_FORMAT and LOG_FILENAME_MAX_LEN\n");
        free(filename);
        filename = NULL;
    }
    return filename;
}

char // returns 0 if ok, 1 otherwise
init_recorder(void)
{
    char * filename = make_filename();
    if (filename == NULL)
        return 1;
    struct timeval tm;
    if (gettimeofday(&tm, NULL) != 0) {
        fprintf(stderr, "OUPS gettimeofday failed!\n");
        return 1;
    }
    recorder_handle = ttyrec_w_open(-1, "ttyrec", filename, &tm);
    free(filename);
    if (recorder_handle == NULL) {
        fprintf(stderr, "Couldn't open the session termrec log file.\n");
        return 1;
    }

    return 0;
}

char // returns 0 if ok, greater than 0 otherwise
record(void* data, size_t len)
{
    if(recorder_handle == NULL)
        return 0;

    struct timeval tm;
    if (gettimeofday(&tm, NULL) != 0) {
        fprintf(stderr, "OUPS gettimeofday failed!\n");
        return 1;
    }
    if (ttyrec_w_write(recorder_handle, &tm, data, (int) len) == 0) {
        fprintf(stderr, "OUPS ttyrec_w_write failed!\n");
        return 2;
    }
    return 0;
}
#endif
