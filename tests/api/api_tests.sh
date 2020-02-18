#!/bin/bash

ARG="$1"
ARG2="$2"
NFTBIN="nft"
NFTLBIN="../../src/nftlb"
DEBUG="7"
#NFTLB_SERIAL=" -S"
NFTLB_SERIAL=""
APISRV_ADDR=localhost
APISRV_PORT=5555
APISRV_KEY="hola"
CURL=`which curl`
CURL_ARGS=""
INDEX=1
STOPPED=0


echo "" > /var/log/syslog

kill `pidof nftlb` 2> /dev/null
$NFTBIN flush ruleset
$NFTLBIN $NFTLB_SERIAL -d -k "$APISRV_KEY" -H $APISRV_ADDR -P $APISRV_PORT -l $DEBUG > /dev/null
sleep 1s

for DIRTEST in `ls -d */`; do
	cd ${DIRTEST}
	TESTCASE=`ls *.api`
	source $TESTCASE
	INDEX_OUT=`printf %03d $INDEX`
	#~ echo -n "$INDEX_OUT - $DESC "
	echo -n "$DIRTEST... "
	logger NFTLB API TESTING $INDEX_OUT - $DESC

	if [ "$VERB" = "POST" ] || [ "$VERB" = "PUT" ]; then
		CURL_ARGS="-d @${FILE}"
	fi
	CURL_OUTPUT="report-${INDEX_OUT}-req.out"
	rm -f report-*-req.out
	echo $CURL -H \"Key: $APISRV_KEY\" -X $VERB $CURL_ARGS http://$APISRV_ADDR:$APISRV_PORT/$URI
	$CURL -H "Key: $APISRV_KEY" -X $VERB $CURL_ARGS http://$APISRV_ADDR:$APISRV_PORT/$URI -o "$CURL_OUTPUT" 2> /dev/null

	# checking curl output
	CHECK_OUTPUT="req.out"
	echo -n "(request:"
	if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
			echo -en "\e[31mFAILURE\e[0m) "
		else
			echo -en "\e[32mOK\e[0m) "
			rm -f report-*-req.out
		fi
	else
		echo -en "\e[33mUNKNOWN\e[0m) "
	fi

	# check nft output
	CHECK_OUTPUT="nft.out"
	NFT_OUTPUT="report-${INDEX_OUT}-nft.out"
	rm -f report-*-nft.out
	echo -n "(nft:"
	$NFTBIN list ruleset > $NFT_OUTPUT
	if [ -f "$CHECK_OUTPUT" ] && [ -f "$NFT_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $NFT_OUTPUT`" != "" ]; then
			echo -en "\e[31mFAILURE\e[0m) "
		else
			echo -en "\e[32mOK\e[0m) "
			rm -f report-*-nft.out
		fi
	else
		echo -en "\e[33mUNKNOWN\e[0m) "
	fi

	# check nftlb objects
	CURL_OUTPUT="report-${INDEX_OUT}-obj.out"
	OBJ=`echo $URI | awk -F'/' '{ printf $1 }'`
	rm -f report-*-obj.out
	$CURL -H "Key: $APISRV_KEY" -X GET http://$APISRV_ADDR:$APISRV_PORT/$OBJ -o "$CURL_OUTPUT" 2> /dev/null

	CHECK_OUTPUT="obj.out"
	echo -n "(objects:"
	if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
			echo -en "\e[31mFAILURE\e[0m) "
		else
			echo -en "\e[32mOK\e[0m) "
			rm -f report-*-obj.out
		fi
	else
		echo -en "\e[33mUNKNOWN\e[0m) "
	fi

	echo ""

	CURL_ARGS=
	INDEX=$(($INDEX+1));
	cd ../

	if [[ "$ARG" = "-stop" ]]; then
		if [[ "${DIRTEST}" == "${ARG2}"* ]]; then
			echo "Stopped."
			STOPPED=1;
			break;
		fi
	fi
done

if [ $STOPPED -eq 0 ]; then
	$NFTBIN flush ruleset
	kill `pidof nftlb`
fi

ERRORS="`grep 'nft command error' /var/log/syslog`"
if [ "$ERRORS" != "" ]; then
	echo -e "\e[33m* command errors found, please check syslog\e[0m"
	echo "$ERRORS"
fi
