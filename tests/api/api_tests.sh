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
	echo -n "$INDEX - $DESC "

	if [ "$VERB" = "POST" ] || [ "$VERB" = "PUT" ]; then
		CURL_ARGS="-d @${FILE}"
	fi

	CURL_OUTPUT="${INDEX_OUT}.out"
	echo $CURL -H \"Key: $APISRV_KEY\" -X $VERB $CURL_ARGS http://$APISRV_ADDR:$APISRV_PORT/$URI
	$CURL -H "Key: $APISRV_KEY" -X $VERB $CURL_ARGS http://$APISRV_ADDR:$APISRV_PORT/$URI -o "$CURL_OUTPUT" 2> /dev/null

	# checking curl output
	CHECK_OUTPUT="${INDEX_OUT}_req.out"
	echo -n "(request:"
	if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
			echo -n "FAILURE) "
		else
			echo -n "OK) "
		fi
	else

		echo -n "UNKNOWN) "
	fi

	rm -f "$CURL_OUTPUT"

	# check nft output
	CHECK_OUTPUT="${INDEX_OUT}_nft.out"
	echo -n "(nft:"
	if [ -f "$CHECK_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT <($NFTBIN list ruleset)`" != "" ]; then
			echo -n "FAILURE) "
		else
			echo -n "OK) "
		fi
	else
		echo -n "UNKNOWN) "
	fi

	# check nftlb objects
	CURL_OUTPUT="${INDEX_OUT}.out"
	$CURL -H "Key: $APISRV_KEY" -X GET http://$APISRV_ADDR:$APISRV_PORT/$URI -o "$CURL_OUTPUT" 2> /dev/null

	CHECK_OUTPUT="${INDEX_OUT}_obj.out"
	echo -n "(objects:"
	if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
		if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
			echo -n "FAILURE) "
		else
			echo -n "OK) "
		fi
	else
		echo -n "UNKNOWN) "
	fi
	rm -f "$CURL_OUTPUT"

	echo ""

	CURL_ARGS=
	INDEX=$(($INDEX+1));
	cd ../
done

$NFTBIN flush ruleset
kill `pidof nftlb`
