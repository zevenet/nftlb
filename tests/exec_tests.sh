#!/bin/bash

ARG="$1"
NFTBIN="nft"
NFTLBIN="../src/nftlb"

if [ "${ARG}" = "" ]; then
	ARG="*.json"
fi

for file in `ls ${ARG}`; do
	echo -n "Executing test: ${file}... "
	$NFTBIN flush ruleset
	$NFTLBIN -e -l 7 -c ${file}
	statusexec=$?

	if [ $statusexec -ne 0 ]; then
		echo -e "\e[31mNFT EXEC ERROR\e[0m"
		continue;
	fi

	nftfile=`echo ${file} | awk -F'.' '{ print $1 }'`

	if [ ! -f "cmd/$nftfile.nft" ]; then
		echo "Dump file doesn't exist"
		continue;
	fi

	diff -Nru "cmd/${nftfile}.nft" <($NFTBIN list ruleset)
	statusnft=$?

	if [ $statusnft -eq 0 ]; then
		echo -e "\e[32mOK\e[0m"
	else
		echo -e "\e[31mNFT DUMP ERROR\e[0m"
	fi

done
