#!/bin/bash

tmp_file=/etc/haproxy/peers.new
cfg_file=/etc/haproxy/peers.cfg

/usr/bin/generate-peers.sh > $tmp_file

tmp_sum=$(md5sum $tmp_file | cut -f1 -d " ")
cfg_sum=$(md5sum $cfg_file | cut -f1 -d " ")

if [ "$tmp_sum" != "$cfg_sum" ]; then
    echo "Checksum changed. Updating haproxy configuration"
    cp $tmp_file $cfg_file;
    systemctl reload haproxy;
fi;
