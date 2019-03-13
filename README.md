# Bastion

SSH bastion that features transparent connection and session recording.

This project is inspired by https://github.com/moul/sshportal. I wrote this implementation to work around the fact that I couldn't get the go ssh lib
to work properly with non interactive sessions, the bug has been open for a long time and I tend to belive it cannot be fixed
(https://github.com/moul/sshportal/issues/55). This one does work properly with non interactive sessions, which allows transparent ansible usage through
the bastion.

## Contents

- [Dependencies](#dependencies)
- [Installation and usage](#manual-installation)
- [Usage](#usage)
- [Docker](#docker)
- [Monitoring](#monitoring)
- [Backup](#backup)
- [Scaling](#scaling)

## Dependencies

This project has only one hard dependency :
- the libssh from https://www.libssh.org/. You should be able to use your distro's packages if they are recent enough.

The following are optional dependencies :
- the libtty from https://github.com/kilobyte/termrec which allows session recording.
- compression libraries like libbz2, liblzma, libz allows to compress on the fly session records.
- libmysql for now because it hosts the runtime config

## Manual Installation

This project is built using cmake :
```
mkdir build
cd build
cmake ..
make
make install
```

You can customise the build with the following cmake flags :
- SESSION_RECORDING

For exemple this disables session recording :
`cmake .. -DSESSION_RECORDING=OFF`

## Usage

## Docker

## Monitoring

## Backup

## Scaling
