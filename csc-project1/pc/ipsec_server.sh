#!/bin/sh

echo 0 > /proc/sys/net/ipv4/tcp_timestamps

vic_ip='172.17.1.1'
serv_ip='172.17.100.254'

# read -p "input victim's port:" vic_port
# read -p "input server's port:" serv_port
vic_port=2222
serv_port=1111

ip xfrm state deleteall
ip xfrm policy deleteall

ip xfrm state add src $vic_ip dst $serv_ip proto esp spi 0x0000c6f8 reqid 1 mode transport auth-trunc "hmac(sha1)" "0xb1f884fc3bc1b61aa0c7c8bcde3e1b7b" 96 enc cipher_null "" sel src $vic_ip dst $serv_ip proto ip sport $vic_port dport $serv_port
ip xfrm state add src $serv_ip dst $vic_ip proto esp spi 0xfb170e3f reqid 2 mode transport auth-trunc "hmac(sha1)" "0xb1f884fc3bc1b61aa0c7c8bcde3e1b7b" 96 enc cipher_null "" sel src $serv_ip dst $vic_ip proto ip sport $serv_port dport $vic_port
ip xfrm state
ip xfrm policy add src $vic_ip dst $serv_ip proto ip sport $vic_port dport $serv_port dir in ptype main tmpl src $vic_ip dst $serv_ip proto esp reqid 1 mode transport
ip xfrm policy add src $serv_ip dst $vic_ip proto ip sport $serv_port dport $vic_port dir out ptype main tmpl src $serv_ip dst $vic_ip proto esp reqid 2 mode transport
ip xfrm policy ls
