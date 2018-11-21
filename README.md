# [nftlb](https://www.zevenet.com/knowledge-base/nftlb)
**nftlb** stands for **nftables load balancer**, the next generation linux firewall that will replace iptables is adapted to behave as a complete load balancer and traffic distributor.

nftlb is provided with a JSON API, so you can use your preferred health checker to enable/disable backends or virtual services and automate processed with it.

More info: [What is nftlb?](https://www.zevenet.com/knowledge-base/nftlb/what-is-nftlb/)

## Repository Contents
In this repository is included:
- **src/**: main source code files
- **include/**: include files
- **tests/**: automated testbed suite with example configuration files and the script *exec_tests.sh* to run all of them.

## Requirements
nftlb uses a quite new technology that requires:

[nf-next](https://git.kernel.org/pub/scm/linux/kernel/git/pablo/nf-next.git/): Latest kernel with the new netfilter developments<br />
[nftables](http://git.netfilter.org/nftables): Latest nftables developments, and its dependencies (libgmp, [libmnl](http://git.netfilter.org/libmnl) and [libnftnl](http://git.netfilter.org/libnftnl))<br />
libev: Events library for the web service<br />
libjansson: JSON parser for the API

## Installation
To build nftlb, just execute:
```
root# autoreconf -fi
root# ./configure
root# make
```
Finally, install it:
```
root# make install
```

## Usage
Check out the command help:
```
# ./nftlb -h
```
Here is the list of options:

**[ -h | --help ]**: Show the command help.<br />
**[ -l &lt;LEVEL&gt; | --log &lt;LEVEL&gt; ]**: The logs will be shown in the syslog file and with this option you can change the loglevel from 0 to 7 (5 by default).<br />
**[ -c &lt;FILE&gt; | --config &lt;FILE&gt; ]**: Initial configuration file, this argument is optional.<br />
**[ -k &lt;KEY&gt; | --key &lt;KEY&gt; ]**: The authentication key for the web service can be set by command line, or automatically generated. If it's automatically generated, it'll be shown by command line.<br />
**[ -e | --exit ]**: This option executes the configuration file into nftables rules and then exit, so the web server won't be available.<br />
**[ -6 | --ipv6 ]**: Enable IPv6 support for the web service listening port.<br />
**[ -H &lt;HOST&gt; | --host &lt;HOST&gt; ]**: Set the host for the web service (all interfaces by default).<br />
**[ -P &lt;PORT&gt; | --port &lt;PORT&gt; ]**: Set the TCP port for the web service (5555 by default).<br />

Note 1: In order to use sNAT or dNAT modes, ensure you have activated the ip forwarding option in your system
Note 2: Before executing nftlb, ensure you have empty nft rules by executing "nft flush ruleset"

### JSON configuration file
The configuration files have the following format:
```
{
	"farms" : [
		{ <object farm 1> },
		{ <object farm 2> },
		{ ... }
	]
}
```
Where every farm object has the following attributes:
```
{
	"name" : "<string>",				*Name of the service (required)*
	"iface"	: "<interface name>",			*Input interface (only required for DSR)*
	"oface"	: "<interface name>",			*Output interface (only required for DSR)*
	"family": "<ipv4 | ipv6 | dual>",		*Family of the virtual service (ipv4 by default)*
	"ether-addr": "<mac address>",			*Physical address of the virtual service (only required for DSR)*
	"virtual-addr": "<ip address>",			*IP address for the virtual service (required)*
	"virtual-ports": "<port list>",			*Port list separated by commas or ranges separated by a hyphen*
	"source-addr": "<ip address>",			*Source IP address instead of masquerading*
	"mode": "<snat | dnat | dsr>",			*Topology to be implemented (required)*
	"protocol": "<tcp | udp | sctp | all>",		*Protocol to be used by the virtual service (tcp by default)*
	"scheduler": "<weight | rr | hash | symhash>",	*Scheduler to be used (round robin by default)*
	"helper": "<none | amanda | ftp | h323 | irc | netbios-ns | pptp | sane | sip | snmp | tftp>",	*L7 helper to be used (none by default)*
	"log": "<none | input | forward | output>",	*Enable logging (none by default)*
	"mark": "<hexadecimal mark>",			*Set mark mask for the farm (none by default)*
	"priority": "<number>",				*Priority availability for backends > 0 (1 by default)*
	"state": "<up | down | off>",			*Set the status of the virtual service (up by default)*
	"backends" : [					*List of backends*
		{<object backend 1>},
		{<object backend 2>},
		{...}
	]
}
```
Where every backend object has the following attributes:
```
{
	"name" : "<string>",				*Name of the backend (required)*
	"ether-addr": "<mac address>",			*Physical address of the backend (only required for DSR)*
	"ip-addr": "<ip address>",			*IP address for the backend (required, except for DSR)*
	"weight": "<number>",				*Weight of the backend (1 by default)*
	"priority": "<number>",				*Priority availability for the backend > 0 (1 by default)*
	"mark": "<hexadecimal mark>",			*Set mark mask for the backend (none by default)*
	"state": "<up | down | off>",			*Set the status of the backend (up by default)*
}
```
You can find some examples in the *tests/* folder.

### API examples
Once launched nftlb you can manage it through the API.

Virtual service listing.
```
curl -H "Key: <MYKEY>" http://<NFTLB IP>:5555/farms
```
Setup a new virtual service.
```
curl -H "Key: <MYKEY>" -X POST http://<NFTLB IP>:5555/farms -d "@tests/008_snat_ipv4_all_rr.json"
```
Add a new backend into a virtual service.
```
curl -H "Key: <MYKEY>" -X POST http://<NFTLB IP>:5555/farms -d '{"farms" : [ { "name" : "myfarm", "backends" : [ { "name" : "mynewbck", "ip-addr" : "192.168.0.150", "state" : "up" } ] } ] }'
```
Delete a virtual service.
```
curl -H "Key: <MYKEY>" -X DELETE http://<NFTLB IP>:5555/farms/lb01
```
Delete a backend of a virtual service.
```
curl -H "Key: <MYKEY>" -X DELETE http://<NFTLB IP>:5555/farms/lb01/backends/bck1
```

## Support
Please refer to the [netfilter users mailing list](http://netfilter.org/mailinglists.html#ml-user)
