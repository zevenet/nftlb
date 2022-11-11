#!/bin/bash

logger ">> PRE"
nft delete element nftlb persist-newfarm { 222.222.222.223 }
nft list map nftlb persist-newfarm | logger
logger "PRE <<"

