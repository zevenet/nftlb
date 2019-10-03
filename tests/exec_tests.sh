#!/bin/bash

ARG="$1"
ARG2="$2"
NFTBIN="nft"
NFTLBIN="../src/nftlb"
#NFTLB_SERIAL=" -S"
NFTLB_SERIAL=""
APISERVER=0
APISRV_PORT=5555
APISRV_KEY="hola"
CURL=`which curl`

TESTS=""

if [ "${ARG}" = "-s" -a -e "$CURL" ]; then
	APISERVER=1
elif [[ -d ${ARG} ]]; then
	TESTS="${ARG}"
elif [ "${ARG}" = "" ]; then
	TESTS="*/"
fi

if [ "$TESTS" = "" -a "${ARG2}" = "" ]; then
	TESTS="*/"
fi

echo "" > /var/log/syslog

if [ $APISERVER -eq 1 ]; then
	$NFTBIN flush ruleset
	$NFTLBIN $NFTLB_SERIAL -d -k "$APISRV_KEY" -l 7 > /dev/null
fi

echo "-- Executing configuration tests"

for test in `ls -d ${TESTS}`; do
	if [[ ! ${test} =~ ^..._ ]]; then
		continue;
	fi

	echo -n "Executing test: ${test}... "

	inputfile="${test}/input.json"
	outputfile="${test}/output.nft"
	reportfile="${test}/report-output.nft"

	if [ $APISERVER -eq 1 ]; then
		$CURL -H "Expect:" -H "Key: $APISRV_KEY" -X DELETE http://localhost:$APISRV_PORT/farms
		$CURL -H "Expect:" -H "Key: $APISRV_KEY" -X POST http://localhost:$APISRV_PORT/farms -d "@${inputfile}"
		statusexec=$?
	else
		$NFTBIN flush ruleset
		$NFTLBIN $NFTLB_SERIAL -e -l 7 -c ${inputfile}
		statusexec=$?
	fi

	if [ $statusexec -ne 0 ]; then
		echo -e "\e[31mNFT EXEC ERROR\e[0m"
		continue;
	fi

	#~ nftfile=`echo ${file} | awk -F'.' '{ print $1 }'`
	$NFTBIN list ruleset > ${reportfile}

	if [ ! -f ${outputfile} ]; then
		echo "Dump file doesn't exist"
		continue;
	fi

	diff -Nru ${outputfile} ${reportfile}
	statusnft=$?

	if [ $statusnft -eq 0 ]; then
		echo -e "\e[32mOK\e[0m"
		rm -f ${reportfile}
	else
		echo -e "\e[31mNFT DUMP ERROR\e[0m"
	fi
done

if [ $APISERVER -eq 1 ]; then
	kill `pidof nftlb`
fi

if [ "`grep 'nft command error' /var/log/syslog`" != "" ]; then
	echo -e "\e[33m* command errors found, please check syslog\e[0m"
fi
