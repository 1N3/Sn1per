#!/bin/bash
# fingertool - This script will enumerate users using finger
# SECFORCE - Antonio Quina

if [ $# -eq 0 ]
	then
		echo "Usage: $0 <IP> [<WORDLIST>]"
		echo "eg: $0 10.10.10.10 users.txt"
		exit
	else
		IP="$1"
fi

if [ "$2" == "" ]
	then
		WORDLIST="/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
	else
		WORDLIST="$2"
fi


for username in $(cat $WORDLIST | sort -u| uniq)
	do output=$(finger -l $username@$IP)
	if [[ $output == *"Directory"* ]]
		then
			echo "Found user: $username"
	fi
	done

echo "Finished!"