#!/bin/sh
set -ex

python2 disOps.py
unix2dos output.txt
cat ../src/insts.c.in output.txt > ../src/insts.c
