#!/bin/bash

dpkg-buildpackage -us -uc -b -j`grep -c ^processor /proc/cpuinfo`
