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
mininet> r2 ftp sh defense/ftp_defense.sh
```

```shell
mininet> r2 ftp sh defense/ssh_deny_ssh.sh
```

### Port Scanning : 
```shell
mininet> internet python3 attacks/network_scan.py
```

*Defense :*
```shell
mininet> r2 protect_network_scan.sh
```

