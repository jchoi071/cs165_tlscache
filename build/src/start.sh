#!/bin/bash

trap killgroup SIGINT

killgroup() {
	echo "killing"
	kill %1;
	kill %2;
	kill %3;
	kill %4;
	kill %5;
	kill %6;
	kill %7;
	trap - SIGINT
}

./proxy -port 9000 -servername 8000 & 
./proxy -port 9001 -servername 8000 & 
./proxy -port 9002 -servername 8000 & 
./proxy -port 9003 -servername 8000 & 
./proxy -port 9004 -servername 8000 & 
./proxy -port 9005 -servername 8000 & 
./server 8000


