#!/bin/bash

ARG="$1"
ARG2="$2"
NFTBIN="nft"
NFTLBIN="../src/nftlb"
APISERVER=0
APISRV_PORT=5555
APISRV_KEY="hola"
CURL=`which curl`

FILES=""

if [ "${ARG}" = "-s" -a -e "$CURL" ]; then
	APISERVER=1
elif [[ ${ARG} =~ '.json' ]]; then
	FILES="${ARG}"
elif [ "${ARG}" = "" ]; then
	FILES="*.json"
fi

if [ "$FILES" = "" -a "${ARG2}" = "" ]; then
	FILES="*.json"
fi

if [ $APISERVER -eq 1 ]; then
	$NFTBIN flush ruleset
	$NFTLBIN -d -k "$APISRV_KEY" -l 7 > /dev/null
fi

echo "-- Executing configuration files tests"

for file in `ls ${FILES}`; do
	echo -n "Executing test: ${file}... "

	if [ $APISERVER -eq 1 ]; then
		$CURL -H "Expect:" -H "Key: $APISRV_KEY" -X DELETE http://localhost:$APISRV_PORT/farms
		$CURL -H "Expect:" -H "Key: $APISRV_KEY" -X POST http://localhost:$APISRV_PORT/farms -d "@$file"
		statusexec=$?
	else
		$NFTBIN flush ruleset
		$NFTLBIN -e -l 7 -c ${file}
		statusexec=$?
	fi

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

if [ $APISERVER -eq 1 ]; then
	kill `pidof nftlb`
fi

# execute api specific test
echo "-- Executing API specific tests"

cd api/
./api_tests.sh
cd ..
