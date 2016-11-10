#!/bin/sh
PORT=33123
if [ $(uci get network.$CONFIG.proto) == gluon_mesh ]
then                                                 
  echo flush interface $IFNAME| telnet ::1 33123         
  grep -v "fw-addif $IFNAME" /tmp/liverules.iptables|sort -u >/tmp/liverules.iptables.$$
  mv /tmp/liverules.iptables.$$ /tmp/liverules.iptables
fi
