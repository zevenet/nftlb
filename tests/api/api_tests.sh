#!/bin/bash

ARG="$1"
ARG2="$2"
NFTBIN="nft"
NFTLBIN="../../src/nftlb"
DEBUG="7"
APISERVER=0
APISRV_ADDR=localhost
APISRV_PORT=5555
APISRV_KEY="hola"
CURL=`which curl`
CURL_ARGS=""
INDEX=1
OUTPUT=0
OUT_FILE="out"

$NFTBIN flush ruleset
$NFTLBIN -d -k "$APISRV_KEY" -H $APISRV_ADDR -P $APISRV_PORT -l $DEBUG > /dev/null
sleep 1s

for DIRTEST in `ls -d */`; do
	cd ${DIRTEST}/
	TESTCASE=`ls *.api`
	source $TESTCASE
	INDEX_OUT=`printf %03d $INDEX`
	echo -n "$INDEX_OUT - $DESC "
	logger NFTLB API TESTING $INDEX_OUT - $DESC

	if [ "$VERB" = "POST" ] || [ "$VERB" = "PUT" ]; then
		CURL_ARGS="-d @${FILE}"
	fi

	CURL_OUTPUT="report-${INDEX_OUT}-req.out"
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
			rm -f "$CURL_OUTPUT"
		fi
	else
		echo -en "\e[33mUNKNOWN\e[0m) "
		rm -f "$CURL_OUTPUT"
	fi

	# check nft output
	CHECK_OUTPUT="nft.out"
	NFT_OUTPUT="report-${INDEX_OUT}-nft.out"
	echo -n "(nft:"
	$NFTBIN list ruleset > $NFT_OUTPUT
	if [ -f "$CHECK_OUTPUT" ] && [ -f  ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $NFT_OUTPUT`" != "" ]; then
			echo -en "\e[31mFAILURE\e[0m) "
		else
			echo -en "\e[32mOK\e[0m) "
			rm -f "$NFT_OUTPUT"
		fi
	else
		echo -en "\e[33mUNKNOWN\e[0m) "
		rm -f "$NFT_OUTPUT"
	fi

	# check nftlb objects
	CURL_OUTPUT="report-${INDEX_OUT}-obj.out"
	OBJ=`echo $URI | awk -F'/' '{ printf $1 }'`
	$CURL -H "Key: $APISRV_KEY" -X GET http://$APISRV_ADDR:$APISRV_PORT/$OBJ -o "$CURL_OUTPUT" 2> /dev/null

	CHECK_OUTPUT="obj.out"
	echo -n "(objects:"
	if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
			echo -en "\e[31mFAILURE\e[0m) "
		else
			echo -en "\e[32mOK\e[0m) "
			rm -f "$CURL_OUTPUT"
		fi
	else
		echo -en "\e[33mUNKNOWN\e[0m) "
		rm -f "$CURL_OUTPUT"
	fi

	echo ""

	CURL_ARGS=
	INDEX=$(($INDEX+1));
	cd ../
done

$NFTBIN flush ruleset
kill `pidof nftlb`
