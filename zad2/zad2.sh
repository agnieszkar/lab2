#!/bin/bash
if [ -f zad2.config ]
then # usage ./zad2.sh [path to music]
    echo -n PIN: 
	read -s pin
	./zad2 "p" "$1" "${pin}" | mpg123 "-"
else # instalation
    echo -n Path to kestore:
    read kestorePath
    echo -n Key id:
    read keyId
    echo -n Password to key:
    read -s keyPassword
    echo -ne '\nPIN:'
    read -s pin
    ./zad2 "f" "${kestorePath}" "${keyPassword}" "${keyId}" "${pin}"
fi