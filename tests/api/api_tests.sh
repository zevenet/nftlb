#!/bin/bash

# Execute one test group stopping once a certain test is found and applying tests corrections
# ./api_tests.sh -g 001_xxx -s 001 -r
# Execute one test group
# ex: ./api_tests.sh -g 001_xxx
# Execute all tests groups
# ex: ./api_tests.sh
# Execute all tests applying tests corrections
# ex: ./api_tests.sh -r

ARG="$1"
ARG2="$2"
ARG3="$3"
ARG4="$4"
NFTBIN="nft"
NFTLBIN="../../src/nftlb"
DEBUG="7"
NFTLB_ARGS=""
APISRV_ADDR=localhost
APISRV_PORT=5555
APISRV_KEY="hola"
CURL=`which curl`
CURL_ARGS=""
STOPPED=0
REPORTS=0
STOP=""
TESTGROUP=""

while getopts "g:s:r" o; do
    case "${o}" in
        g)
            TESTGROUP=${OPTARG}
            ;;
        s)
            STOP=${OPTARG}
            ;;
        r)
            REPORTS=1
            ;;
        *)
            ;;
    esac
done
shift $((OPTIND-1))

echo "" > /var/log/syslog

for DIRTEST0 in `ls -d */`; do
	if [ "$TESTGROUP" != "" ] && [[ "${TESTGROUP}" != "${DIRTEST0}"* ]]; then
		continue
	fi

kill -9 `pidof nftlb` 2> /dev/null
$NFTBIN flush ruleset
$NFTLBIN $NFTLB_ARGS -d -k "$APISRV_KEY" -H $APISRV_ADDR -P $APISRV_PORT -l $DEBUG > /dev/null
sleep 1s

	echo "$DIRTEST0: "
	cd ${DIRTEST0}

	for DIRTEST in `ls -d */`; do
		cd ${DIRTEST}

		TESTCASE=`ls *.api`
		source $TESTCASE
		echo -nE "  $DIRTEST "
		logger NFTLB API TESTING - $DESC

		FEXEC="pre.sh"
		if [ -x $FEXEC ]; then
			./$FEXEC
		fi

		if [ "$VERB" = "POST" ] || [ "$VERB" = "PUT" ] || [ "$VERB" = "DELETE" ] || [ "$VERB" = "PATCH" ]; then
			if [ -e "${FILE}" ]; then
				CURL_ARGS="-d @${FILE}"
			fi
		fi
		CURL_OUTPUT="report-req.out"
		rm -f report-*-req.out
		$CURL -H "Key: $APISRV_KEY" -X $VERB $CURL_ARGS http://$APISRV_ADDR:$APISRV_PORT/$URI -o "$CURL_OUTPUT" 2> /dev/null

		FEXEC="pos.sh"
		if [ -x $FEXEC ]; then
			./$FEXEC
		fi

		# checking curl output
		CHECK_OUTPUT="req.out"
		echo -n "(request:"
		if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
			if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
				echo -en "\e[31mFAILURE\e[0m) "
				diff -Nru $CHECK_OUTPUT $CURL_OUTPUT
				if [ $REPORTS -eq 1 ]; then
					cat $CURL_OUTPUT > $CHECK_OUTPUT
					echo -en "APPLIED "
				fi
			else
				echo -en "\e[32mOK\e[0m) "
				rm -f report-*-req.out
			fi
		else
			echo -en "\e[33mUNKNOWN\e[0m) "
		fi

		# check nft output
		CHECK_OUTPUT="nft.out"
		NFT_OUTPUT="report-nft.out"
		rm -f report-*-nft.out
		echo -n "(nft:"
		$NFTBIN list ruleset > $NFT_OUTPUT
		if [ -f "$CHECK_OUTPUT" ] && [ -f "$NFT_OUTPUT" ]; then
			if [ "`diff -Nru $CHECK_OUTPUT $NFT_OUTPUT`" != "" ]; then
				echo -en "\e[31mFAILURE\e[0m) "
				diff -Nru $CHECK_OUTPUT $NFT_OUTPUT
				if [ $REPORTS -eq 1 ]; then
					cat $NFT_OUTPUT > $CHECK_OUTPUT
					echo -en "APPLIED "
				fi
			else
				echo -en "\e[32mOK\e[0m) "
				rm -f report-*-nft.out
			fi
		else
			echo -en "\e[33mUNKNOWN\e[0m) "
		fi

		# check nftlb objects
		CURL_OUTPUT="report-obj.out"
		OBJ=`echo $URI | awk -F'/' '{ printf $1 }'`
		rm -f report-*-obj.out
		$CURL -H "Key: $APISRV_KEY" -X GET http://$APISRV_ADDR:$APISRV_PORT/$OBJ -o "$CURL_OUTPUT" 2> /dev/null

		CHECK_OUTPUT="obj.out"
		echo -n "(objects:"
		if [ -f "$CHECK_OUTPUT" ] && [ -f "$CURL_OUTPUT" ]; then
			if [ "`diff -Nru $CHECK_OUTPUT $CURL_OUTPUT`" != "" ]; then
				echo -en "\e[31mFAILURE\e[0m) "
				diff -Nru $CHECK_OUTPUT $CURL_OUTPUT
				if [ $REPORTS -eq 1 ]; then
					cat $CURL_OUTPUT > $CHECK_OUTPUT
					echo -en "APPLIED "
				fi
			else
				echo -en "\e[32mOK\e[0m) "
				rm -f report-*-obj.out
			fi
		else
			echo -en "\e[33mUNKNOWN\e[0m) "
		fi

		echo ""

		CURL_ARGS=
		cd ../

		if [ "${STOP}" != "" ] && [[ "${DIRTEST}" == "${STOP}"* ]]; then
			echo "Stopped."
			STOPPED=1;
			break;
		fi
	done
	cd ../

	$NFTBIN flush ruleset
	kill `pidof nftlb`

	if [ "$STOPPED" == "1" ]; then
		break;
	fi
done

ERRORS="`grep 'nft command error' /var/log/syslog`"
if [ "$ERRORS" != "" ]; then
	echo -e "\e[33m* command errors found, please check syslog\e[0m"
	echo "$ERRORS"
fi
