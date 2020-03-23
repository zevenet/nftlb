#!/bin/bash

logger ">> PRE"
nft add element nftlb persist-newfarm { 222.222.222.222 : 0x200 }
nft list map nftlb persist-newfarm | logger
logger "PRE <<"

