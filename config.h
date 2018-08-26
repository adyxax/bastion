#ifndef CONFIG_H_
#define CONFIG_H_

#define USER_TO_LOGIN_AS "root"

#define LISTEN_PORT 2222
#define MAX_HOSTNAME_LENGTH 255
#define MAX_USERNAME_LENGTH 255
#define USER_RSA_PUBKEY "AAAAB3NzaC1yc2EAAAADAQABAAACAQDMdBAFjENiPMTtq90GT3+NZ68nfGxQiRExaYYnLzm1ecmulCvsuA4AOpeLY6f+FWe+ludiw7nhrXzssDdsKBy0QL+XQyvjjjW4X+k9MYhP1gAWXEOGJnjJ/1ovEsMt++6fLyNKLUTA46kErbEehDs22r+rIiEKatrn0BNrJcRI94H44oEL1/ImzVam0cSBL0tPiaJxe60sBs7M76zfyFtVdMGkeuBpS7ee+FLA58fsS3/sEZmkas8MT0QdvZz1y/66MknXYbIaqDSOUACXGF4yVKpogLRRJ1SgNo1Ujo/U3VOR1O4CiQczsZOcbSdjgl0x3fJb7BaIxrZy9iW2I7G/L/chfTvRws+x1s1y5FNZOOiXMCdZjhgLaRwb6p5gMsMVn9sJbhDjmejcAkBKQDkzbvxxhfVkH225FoVXA9YF0msWLyOEyZQYbA8autLDJsAOT5RDfw/G82DQBufAPEBR/bPby0Hl5kjqW75bpSVxDvzmKwt3EpITg9iuYEhvYZ/Zq5qC1UJ54ZfOvaf0PsTUzFePty6ve/JzfxCV1XgFQ+B8l4NSz11loDfNXSUngf7lL4qu5X4aN6WmLFO1YbyFlfpvt3K1CekJmWVeE5mV9EFTUJ4ParVWRGiA4W+zaCOsHgRkcGkp4eYGyWW8gOR/lVxYU2IFl9mbMrC9bkdRbQ=="
#define PRIVKEY_PATH "./id_rsa"

#define DSAKEY_PATH "./ssh_host_dsa_key"
#define RSAKEY_PATH "./ssh_host_rsa_key"
#define ECDSAKEY_PATH "./ssh_host_ecdsa_key"

#define SESSION_RECORDING  // comment this to deactivate
#define LOG_FILENAME_FORMAT "./log/$d/$h/$u/$i.gz" // $d : date in iso format, $h : hostname, $u : username : $i session id
#define LOG_FILENAME_MAX_LEN 255
#define LOG_DIRECTORY_MODE S_IRUSR | S_IWUSR | S_IXUSR

#define LIBSSH_VERBOSE_OUTPOUT // comment this to deactivate

#endif
