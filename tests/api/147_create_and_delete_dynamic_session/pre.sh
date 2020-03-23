#!/bin/bash

logger ">> PRE"
nft add element netdev nftlb persist-newfarm { 222.222.222.222 : 127.0.0.2 }
nft list map netdev nftlb persist-newfarm | logger
logger "PRE <<"

