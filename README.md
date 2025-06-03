[![Build Status](https://github.com/yeti-switch/sems-yeti/actions/workflows/build.yml/badge.svg)](https://github.com/yeti-switch/sems-yeti/actions/workflows/build.yml)
[![Made in Ukraine](https://img.shields.io/badge/made_in-ukraine-ffd700.svg?labelColor=0057b7)](https://stand-with-ukraine.pp.ua)

[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct-team.svg)](https://stand-with-ukraine.pp.ua)


# sems-yeti

sems-yeti is a part of project [Yeti]

## Installation via Package (Debian 11)
```sh
# apt install wget gnupg

# echo "deb [arch=amd64] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list
# wget -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg

# echo "deb [arch=amd64] https://deb.yeti-switch.org/debian/1.14 bookworm main" > /etc/apt/sources.list.d/yeti.list
# wget http://deb.yeti-switch.org/yeti.gpg -O /etc/apt/trusted.gpg.d/deb.yeti-switch.org.asc

# apt update
# apt install sems-modules-yeti
```
check [Documentation] for additional versions/distributions info

## Building from sources (Debian 11)

### install prerequisites
```sh
# apt install git cmake build-essential devscripts
```

### get sources
```sh
$ git clone git@github.com:yeti-switch/sems-yeti.git
$ cd sems-yeti
```

### install build dependencies
```sh
# apt build-deps .
```

### build package
```sh
$ dpkg-buildpackage -us -uc -b -j$(nproc)
```

[Yeti]:http://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
