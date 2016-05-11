#!/bin/sh
mkdir -p ebin
erl -pa ../ejabberd-dev/ebin -pz ebin -make
