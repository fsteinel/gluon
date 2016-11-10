#!/bin/sh
pidfile='/var/run/babeld.pid'
CONFIGFILE='/var/etc/gluon-babel.conf'
PORT=33123

mkdir -p /var/run


if [ $(uci get network.$CONFIG.proto) == gluon_mesh ]
then 
	# start babel if it is not already running                                                
	if [ ! -f "$pidfile" ]
	then
	  mkdir -p /var/lib
	  mkdir -p /var/etc

	  /lib/gluon/gluon-mesh-babel/mkconfig "$CONFIGFILE" "$IFNAME"
	  /usr/sbin/babeld -D -I "$pidfile" -G $PORT -c "$CONFIGFILE"
	  # Wait for the pidfile to appear
	  for i in 1 2 3 4 5
	  do
	    [ -f "$pidfile" ] || sleep 1
	  done
	  [ -f "$pidfile" ] || (echo "Failed to start babeld"; exit 42)
	  # let babel settle befor continuing adding interfaces. yes this is an ugly hack.
	  sleep 2
	  /usr/sbin/mmfd &
	fi
  
    echo /lib/gluon/gluon-mesh-babel/fw-addif $IFNAME  >> /tmp/liverules.iptables
    /etc/init.d/firewall restart
    echo interface $IFNAME| telnet ::1 $PORT 
fi
