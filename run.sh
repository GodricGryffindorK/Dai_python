#!/bin/bash

if [ "$1" = "2" ]; then
	pcap_file=$2
	config_file=$3
	log_path=$4
	python3 arp_checker.py $pcap_file $config_file $log_path
elif [ "$1" = "3" ]; then
	pcap_file=$2
	log_path=$3
	python3 dai_arp_parser.py $pcap_file $log_path
else
	echo "Incorrect Option chosen, available: 2, 3"
	exit 1
fi
#python3 dai_arp_parser.py
#cat task3.log
