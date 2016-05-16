#!/bin/sh
cp ebin/*.beam /usr/lib64/ejabberd/ebin/ && \
cp include/*hrl /usr/lib64/ejabberd/include && \
ejabberdctl update mod_log_chat_elasticsearch
