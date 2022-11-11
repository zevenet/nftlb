#!/bin/bash

logger ">> PRE"
nft add element netdev nftlb persist-lb01 { 222.222.222.222 : 01:01:01:01:01:01 }
nft list map netdev nftlb persist-lb01 | logger
logger "PRE <<"

