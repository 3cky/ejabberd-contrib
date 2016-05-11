#!/bin/sh
mkdir -p ebin
erl -pa ../ejabberd-dev/trunk/ebin -pz ebin -make
