#!/bin/bash

logger ">> PRE"
nft add element nftlb persist-newfarm { 222.222.222.222 : 0x80000202, 222.222.222.223 : 0x80000201 }
nft list map nftlb persist-newfarm | logger
logger "PRE <<"

