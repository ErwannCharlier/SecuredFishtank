# LINFO2347 - Network Attacks

---
## Base firewall rules

To protect our network we applied two different set of rules. One for the router (r2) protecting the DMZ which also filters for the LAN Networks, and a firewall to protect further the LAN on the router 1.

### *Router 1: LAN-DMZ*

```sql
table inet filter {
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state invalid drop
		ct state established,related accept
		ip saddr 10.1.0.0/24 accept
	}
}
```
The filter above has a default policy of dropping packets. It only allows established connections and packet with a source address from the range 10.1.x.x/24 (our LAN network).


### *Router 2: DMZ-INTERNET*

```sql
table inet filter {
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state invalid drop
		ct state established,related accept
		ip saddr 10.1.0.0/24 accept
		ip saddr 10.2.0.0/24 ip daddr { 10.12.0.10, 10.12.0.20, 10.12.0.30, 10.12.0.40 } accept
	}
}
```
The filter above is located on R2 between the DMZ and the Internet. It also has a default policy of dropping. It allows all the traffic coming from from the range 10.1.x.x/24. It also allows in the traffic from the internet to the DMZ servers. It does so by checking the source address range and the destination IP.

### *DMZ Server rules*

```sql
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}

	chain output {
		type filter hook output priority filter; policy drop;
		oif "lo" accept
		ct state established,related accept
	}
}
```
This filter is placed on each server in the DMZ. This filter contains two chain. One for incoming traffic and one for outgoing traffic.

The input chain allows all the incoming traffic without exception.

The output chains only allows outgoing traffic to the loopback interface (to allow localhost tests). It also accepts established connections, allowing the different servers to answer requests.

---
## User guide - *Attacks and defense*


### Start the topology : 
```shell
sudo -E python3 topo.py
```


### SSH & FTP Bruteforce : 

*FTP* : 
```shell
mininet> internet python3 attacks/bruteforce.py -t "10.12.0.40" -p "ftp"
```

*SSH* : 
```shell
mininet> internet python3 attacks/bruteforce.py -t "10.12.0.10" -p "ssh"
```

*Arguments :*

--protocol / -p < "ssh" or "ftp" >  => Choose between an SSH or FTP bruteforce

--target / t < target > => Ip of the target

*Defense :* 

```shell
mininet> ftp sh defense/ftp_defense.sh
```

```shell
mininet> r2 sh defense/ssh_deny_ssh.sh
```

### Port Scanning : 
```shell
mininet> internet python3 attacks/network_scan.py
```

*Defense :*
```shell
mininet> r2 protect_network_scan.sh
```

### ARP Poisoning

The ARP poisoning attack is launched from `ws2`.  
The goal is to poison the ARP cache of `ws3` by pretending that the gateway `r1` has the MAC address of `ws2`.

```shell
mininet> ws2 sh -c "python3 -u attacks/arp_poisoning.py > /tmp/arp_attack.log 2>&1 &"
````

We run it in the background because the attack continuously sends fake ARP replies, while we still need to use the Mininet terminal.

To test that the attack worked, run:

```shell
mininet> ws3 ip neigh show 10.1.0.1
```

Expected result: `10.1.0.1` is mapped to the MAC address of `ws2`.

Run the defense:

```shell
mininet> ws2 sh defense/protect_arp_poisoning.sh
mininet> ws3 sh defense/protect_arp_poisoning.sh
mininet> r1 sh defense/protect_arp_poisoning.sh
```

Test the defense:

```shell
mininet> ws2 sh -c "python3 -u attacks/arp_poisoning.py > /tmp/arp_attack.log 2>&1 &"
mininet> ws3 sh -c "ping -c 1 10.1.0.1 >/dev/null && ip neigh show 10.1.0.1 && nft list table arp arp_guard"
```

Expected result: `10.1.0.1` still points to the real MAC address of `r1`, and the nftables counter shows dropped packets.



### IP Spoofing

The IP spoofing attack is launched from `internet`.

The attacker sends ICMP packets to `ws3`, but with a fake source IP address.  
Instead of using its real IP address `10.2.0.2`, the attacker pretends to be `ws2` with the IP address `10.1.0.2`.

The goal is to bypass the basic firewall.  
Our firewall trusts packets with a source IP from the LAN network `10.1.0.0/24`, but it does not check if the packet really comes from the LAN side.

Run a packet capture on `ws3`:


```shell
mininet> ws3 tcpdump -n -c 10 -i ws3-eth0 'icmp and src 10.1.0.2 and dst 10.1.0.3' &
````

Launch the attack from `internet`:

```shell
mininet> internet python3 attacks/ip_spoofing_attack.py
```

After the attack, stop the packet capture:

```shell
mininet> ws3 pkill tcpdump
```

Expected result: `ws3` receives ICMP packets that seem to come from `10.1.0.2`, even though they were sent from `internet`.

Run the defense on `r2`:

```shell
mininet> r2 sh defense/protect_ip_spoofing.sh
```

The defense is placed on `r2` because spoofed packets come from the Internet side.

It adds anti-spoofing rules in the `forward` chain.  
If a packet enters `r2` through the Internet interface `r2-eth0`, but its source IP address belongs to the workstation LAN `10.1.0.0/24` or to the DMZ `10.12.0.0/24`, the packet is dropped.

This means that a packet coming from the Internet cannot pretend to come from inside the enterprise network.

```shell
iifname "r2-eth0" ip saddr 10.1.0.0/24 counter drop
iifname "r2-eth0" ip saddr 10.12.0.0/24 counter drop
```

Test the defense:

```shell
mininet> ws3 tcpdump -n -c 10 -i ws3-eth0 'icmp and src 10.1.0.2 and dst 10.1.0.3' &
mininet> internet python3 attacks/ip_spoofing_attack.py
mininet> ws3 pkill tcpdump
```

Expected result: `ws3` receives no spoofed packets anymore.

This protection does not block normal traffic from the Internet to the DMZ servers.  
It only blocks packets that enter from the Internet while using a fake internal source address.