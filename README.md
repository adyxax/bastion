# Bastion

SSH bastion that features transparent connection and session recording.

This project is inspired by https://github.com/moul/sshportal. I wrote this implementation to work around the fact that I couldn't get the go ssh lib
to work properly with non interactive sessions, the bug has been open for a long time and I tend to belive it cannot be fixed
(https://github.com/moul/sshportal/issues/55).

This bastion project does work properly with non interactive sessions, which allows transparent ansible usage through the bastion.

## Contents

- [Dependencies](#dependencies)
- [Manual installation](#manual-installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Docker](#docker)
- [Monitoring](#monitoring)
- [Backup](#backup)
- [Scaling](#scaling)
- [Special thanks](#special-thanks)

## Dependencies

This project has only two hard dependencies :
- the libconfig from http://www.hyperrealm.com/libconfig/libconfig.html
- the libssh from https://www.libssh.org/. You should be able to use your distro's packages if they are recent enough.

The following are optional dependencies :
- the libtty from https://github.com/kilobyte/termrec which allows session recording.
- compression libraries like libbz2, liblzma, libz allow on the fly compression of session records.

## Manual Installation

This project is built using cmake :
```
git submodule update --init
mkdir build
cd build
cmake ..
make
make install
```

You can customise the build with the following cmake flags :

- `CMAKE_BUILD_TYPE` : Debug|Release|RelWithDebInfo|MinSizeRel, defaults to Release if using a tarball, and Debug if using the git tree
- `CMAKE_INSTALL_PREFIX` : path, defaults to `/usr/local`
- `SESSION_RECORDING` : ON|OFF, defaults to ON

For exemple this disables session recording for a debug build and installs the bastion for your current user :

`cmake .. -DCMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX=$HOME/.local -DSESSION_RECORDING=OFF`

## Configuration

Here is the default configuration :
```
port = 2222;

keys:
{
    dsa = "/home/julien/.local/etc/bastion/ssh_host_dsa_key";
    rsa = "/home/julien/.local/etc/bastion/ssh_host_rsa_key";
    ecdsa = "/home/julien/.local/etc/bastion/ssh_host_ecdsa_key";
};

session_recording:
{
    path = "/home/julien/.local/var/log/bastion/$d/$h/$u/$i.gz";     # $d : date in iso format, $h : hostname, $u : username : $i session id
};
```

## Usage

## Docker

## Monitoring

## Backup

## Scaling

## Special thanks

I would like to thank the developers of the following projects, I am merely standing on the shoulders of giants :

- libconfig from http://www.hyperrealm.com/libconfig/libconfig.html
- libssh from https://www.libssh.org/
- libtty from https://github.com/kilobyte/termrec
- uthash from http://troydhanson.github.io/uthash/
