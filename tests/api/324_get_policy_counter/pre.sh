#!/bin/bash

logger ">> PRE"
timeout 2s nc 127.0.0.1 80
nft list set netdev nftlb black001 | logger
logger "PRE <<"

