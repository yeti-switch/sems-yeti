[![Build Status](https://github.com/yeti-switch/sems-yeti/actions/workflows/build.yml)](https://github.com/yeti-switch/sems-yeti/actions/workflows/build.yml/badge.svg)
# sems-yeti

sems-yeti is a part of project [Yeti]

## Installation via Package (Debian 10)
```sh
# echo "deb [arch=amd64] http://pkg.yeti-switch.org/debian/buster 1.10 main" > /etc/apt/sources.list.d/yeti.list
# wget -O- https://pkg.yeti-switch.org/key.gpg | apt-key add -
# apt update
# apt install sems-modules-yeti
```
check [Documentation] for additional versions/distributions info

## Building from sources (Debian 10)

### install prerequisites
```sh
# apt install git cmake build-essential devscripts
```

### get sources
```sh
$ git clone git@github.com:yeti-switch/sems-yeti.git
$ cd sems-yeti
```

### build and install dependencies package
```sh
# mk-build-deps -i
```

### build package
```sh
$ debuild -us -uc -b -j$(nproc)
```

[Yeti]:http://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
