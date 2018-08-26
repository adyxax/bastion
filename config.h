#ifndef CONFIG_H_
#define CONFIG_H_

#define LISTEN_PORT 2222
#define MAX_HOSTNAME_LENGTH 64
#define MAX_USERNAME_LENGTH 64

#define DSAKEY_PATH "./ssh_host_dsa_key"
#define RSAKEY_PATH "./ssh_host_rsa_key"
#define ECDSAKEY_PATH "./ssh_host_ecdsa_key"

#define MYSQL_HOST "::"
#define MYSQL_USER "root"
#define MYSQL_PASS "graou"
#define MYSQL_DB "sshportal"

#define SESSION_RECORDING  // comment this to deactivate
#define LOG_FILENAME_FORMAT "./log/$d/$h/$u/$i.gz" // $d : date in iso format, $h : hostname, $u : username : $i session id
#define LOG_FILENAME_MAX_LEN 255
#define LOG_DIRECTORY_MODE S_IRUSR | S_IWUSR | S_IXUSR

#define LIBSSH_VERBOSE_OUTPOUT // comment this to deactivate

#endif
