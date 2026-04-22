#!/bin/sh

echo "Adding SSH rules to deny outside SSH requests"

nft insert rule inet filter forward iifname "r2-eth0" tcp dport ssh drop


echo "New table :"
nft list chain inet filter forward