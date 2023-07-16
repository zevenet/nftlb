# [nftlb](https://www.zevenet.com/knowledge-base/nftlb)
**nftlb** stands for **nftables load balancer**, the next generation linux firewall that will replace iptables is adapted to behave as a complete load balancer and traffic distributor.

nftlb is provided with a JSON API, so you can use your preferred health checker to enable/disable backends or virtual services and automate processes with it.

More info: [What is nftlb?](https://www.zevenet.com/knowledge-base/nftlb/what-is-nftlb/)

## Repository Contents
In this repository is included:
- **src/**: main source code files.
- **include/**: include files.
- **tests/**: automated testbed suite with example configuration files and the script *exec_tests.sh* to run all of them.
- **tests/api**: automated testbed suite for API interaction and the script *api_tests.sh* to run all of them.

## Requirements
nftlb depends on:

- **linux-kernel**: Kernel version 4.19 or higher with nftables modules enabled (iptables, ebtables, etc not required).
- **nftables**: nftables package with **libnftables** included and its dependencies (**libgmp**, **libmnl** and **libnftnl**).
- **libev**: Events library for the web service.
- **libjansson**: JSON parser for the API.

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

Also, [deb packages](https://repology.org/project/nftlb/versions) are available.

## Usage
Check out the command help:
```
# ./nftlb -h
```
Here is the list of options:

**[ -h | --help ]**: Show the command help.<br />
**[ -l &lt;LEVEL&gt; | --log &lt;LEVEL&gt; ]**: The logs will be shown in the syslog file and with this option you can change the loglevel from 0 to 7 (5 by default).<br />
**[ -L &lt;OUTPUT&gt; | --log-output &lt;OUTPUT&gt; ]**: Set the daemon logs output (0: syslog - default, 1: stdout, 2: stderr, 3: syslog+stdout, 4: syslog+stderr).<br />
**[ -c &lt;FILE&gt; | --config &lt;FILE&gt; ]**: Initial configuration file, this argument is optional.<br />
**[ -k &lt;KEY&gt; | --key &lt;KEY&gt; ]**: The authentication key for the web service can be set by command line, or automatically generated. If it's automatically generated, it'll be shown by command line.<br />
**[ -e | --exit ]**: This option executes the configuration file into nftables rules and then exit, so the web server won't be available.<br />
**[ -d | --daemon ]**: Run nftlb as a daemon in background.<br />
**[ -6 | --ipv6 ]**: Enable IPv6 support for the web service listening port.<br />
**[ -H &lt;HOST&gt; | --host &lt;HOST&gt; ]**: Set the host for the web service (all interfaces by default).<br />
**[ -P &lt;PORT&gt; | --port &lt;PORT&gt; ]**: Set the TCP port for the web service (5555 by default).<br />
**[ -S | --serial ]**: Serialize nft commands.<br />
**[ -m &lt;MARK&gt; | --masquerade-mark &lt;MARK&gt; ]**: Set masquerade mark in hex (80000000 by default).<br />


Note: In order to use sNAT or dNAT modes, ensure you have activated the ip forwarding option in your system.

### Controlling the server behaviour using environment variables
You can also specify a custom server key via the `NFTLB_SERVER_KEY` environment variable. Zero length keys will be ignored.

```
root# NFTLB_SERVER_KEY="changeme" nftlb -d
```

### JSON configuration file
The configuration files have the following format:
```
{
	"farms" : [
		{ <object farm 1> },
		{ <object farm 2> },
		{ ... }
	],
	"addresses" : [
		{ <object address 1> },
		{ <object address 2> },
		{ ... }
	],
	"policies" : [
		{ <object policy 1> },
		{ <object policy 2> },
		{ ... }
	]
}
```
Where every farm object has the following attributes:
```
{
	"name" : "<string>",				*Name of the service (required)*
	"family": "<ipv4 | ipv6 | dual>",		*Family of the virtual service (ipv4 by default)*
	"virtual-addr": "<ip address>",			*IP address for the virtual service (OBSOLETE)*
	"virtual-ports": "<port list>",			*Port list separated by commas or ranges separated by a hyphen*
	"source-addr": "<ip address>",			*Source IP address instead of masquerading*
	"mode": "<snat | dnat | dsr | stlsdnat | local>",	*Topology to be implemented (required)*
	"protocol": "<tcp | udp | sctp | all>",		*Protocol to be used by the virtual service (tcp by default)*
	"scheduler": "<weight | rr | hash | symhash>",	*Scheduler to be used (round robin by default)*
	"sched-param": "<srcip | dstip | srcport | dstport | srcmac | dstmac | none>",	*Hash input parameters (none by default)*
	"persistence": "<srcip | dstip | srcport | dstport | srcmac | dstmac | none>",	*Configured stickiness between client and backend (none by default)*
	"persist-ttl": "<number>",	*Stickiness timeout in seconds (60 by default)*
	"helper": "<none | ftp | pptp | sip | snmp | tftp>",	*L7 helper to be used (none by default)*
	"log": "<none | input | forward | output>",	*Enable logging (none by default)*
	"log-prefix": "<string|KNAME|TYPE|FNAME|ANAME>",	*Farm log prefix (default "TYPE-FNAME")*
	"log-rtlimit": "<number>[/<second | minute | hour | day | week >]",			*Security logs rate limit (0/second by default)*
	"mark": "<hexadecimal mark>",			*Set mark mask for the farm (none by default)*
	"priority": "<number>",				*Priority availability for backends > 0 (1 by default)*
	"limits-ttl": "<number>",				*Timeout of banned client due to limit protections (120 seconds by default)*
	"new-rtlimit": "<number>[/<second | minute | hour | day | week >]",				*Number of new connections per service (0/second by default)*
	"new-rtlimit-burst": "<number>",			*Number of burst packets (disabled by default)*
	"new-rtlimit-log-prefix": "<string|KNAME|TYPE|FNAME>",	*Farm new rtlimit log prefix (default "KNAME-TYPE-FNAME")*
	"rst-rtlimit": "<number>[/<second | minute | hour | day | week >]",				*Number of tcp resets allowed (0/second by default)*
	"rst-rtlimit-burst": "<number>",			*Number of burst RST packets (disabled by default)*
	"rst-rtlimit-log-prefix": "<string|KNAME|TYPE|FNAME>",	*Farm reset rtlimit log prefix (default "KNAME-TYPE-FNAME")*
	"est-connlimit": "<number>",				*Number of established connections allowed (disabled by default)*
	"est-connlimit-log-prefix": "<string|KNAME|TYPE|FNAME>",	*Farm established connlimit log prefix (default "KNAME-TYPE-FNAME")*
	"tcp-strict": "<on | off>",				*Option to avoid bogus TCP attacks (disabled by default)*
	"tcp-strict-log-prefix": "<string|KNAME|TYPE|FNAME>",	*Farm TCP strict log prefix (default "KNAME-TYPE-FNAME")*
	"verdict": "<log | drop | accept>",			*Verdict to apply when a limit or blacklist/whitelist matches (log and default verdict per list type by default)*
	"flow-offload": "<on | off>",				*Option to enable flow offload (disabled by default)*
	"intra-connect": "<on | off>",				*Option to enable connectivity from the local machine (disabled by default)*
	"queue": "<number>",				*Number of the queue to send the packets to userspace (disabled by default)*
	"state": "<up | down | off | config_error>",			*Set the status of the virtual service (up by default)*
	"addresses" : [					*List of addresses*
		{<object address 1>},
		{<object address 2>},
		{...}
	],
	"backends" : [					*List of backends*
		{<object backend 1>},
		{<object backend 2>},
		{...}
	],
	"sessions" : [					*List of static sessions. It requires persistence enabled.*
		{
		{<object session 1>},
		{<object session 2>},
		{...}
	],
	"policies" : [					*List of policies*
		{
			"name" : "<policy name>",
		},
		{...}
	]
}
```
Where every address object has the following attributes:
```
{
	"name" : "<string>",				*Name of the address (required)*
	"family": "<ipv4 | ipv6 | dual>",		*Family of the address (ipv4 by default)*
	"ip-addr": "<ip address>",			*IP address*
	"ports": "<port list>",				*Port list separated by commas or ranges separated by a hyphen*
	"protocol": "<tcp | udp | sctp | all>",		*Protocol to be used by the address (tcp by default)*
	"verdict": "<log | drop | accept>",			*Verdict to apply when a limit or blacklist/whitelist matches (log and default verdict per list type by default)*
	"log-prefix": "<string|KNAME|TYPE|FNAME|ANAME>",	*Address log prefix (default "TYPE-FNAME")*
	"log-rtlimit": "<number>[/<second | minute | hour | day | week >]",			*Security logs rate limit per second (0/second by default)*
}
```
Where every backend object has the following attributes:
```
{
	"name" : "<string>",				*Name of the backend (required)*
	"ip-addr": "<ip address>",			*IP address for the backend (required)*
	"port": "<number>",				*Backend port to redirect the connections*
	"source-addr": "<ip address>",			*Source IP address for a certain backend instead of masquerading or virtual service source address*
	"weight": "<number>",				*Weight of the backend (1 by default)*
	"priority": "<number>",				*Priority availability for the backend > 0 (1 by default)*
	"mark": "<hexadecimal mark>",			*Set mark mask for the backend (none by default)*
	"est-connlimit": "<number>",			*Number of established connections allowed per backend (disabled by default)*
	"est-connlimit-log-prefix": "<string|KNAME|TYPE|FNAME|BNAME>",	*Backend established connections log prefix (default "KNAME-FNAME-BNAME")*
	"state": "<up | down | off | available | config_error>",			*Set the status of the backend (up by default)*
}
```
Where every session object has the following attributes:
```
{
	"client" : "<ip address>",			*Client with the same format than persistence configuration*
	"backend": "<backend id>",			*Backend ID to set a stickyness between client and backend*
	"expiration": "<time>"				*Dynamic sessions timeout. Static sessions doesn't include this attribute*
}
```
Where every policy object has the following attributes:
```
{
	"name" : "<string>",				*Name of the policy (required)*
	"type": "<blacklist | whitelist>",			*Policy type*
	"family": "<ipv4 | ipv6>",			*Family of the policy (ipv4 by default)*
	"log-prefix": "<string|KNAME|TYPE|FNAME|PNAME>",	*Policy established connections log prefix (default "KNAME-TYPE-PNAME-FNAME")*
	"elements" : [					*List of IPs or networks*
		{
			"data" : "<ip or network>"
		},
		{...}
	]
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
Get the static and dynamic sessions.
```
curl -H "Key: <MYKEY>" -X GET http://<NFTLB IP>:5555/farms/lb01/sessions
```
Addresses listing.
```
curl -H "Key: <MYKEY>" http://<NFTLB IP>:5555/addresses
```
Addresses listing.
```
curl -H "Key: <MYKEY>" http://<NFTLB IP>:5555/addresses
```
Create a new address.
```
curl -H "Key: <MYKEY>" -X POST http://<NFTLB IP>:5555/addresses -d '{ "addresses" : [ { "name" : "myaddr", "family": "ipv4", "ip-addr" : "192.168.0.150", "ports": "8080", "protocol": "tcp" } ] }'
```
Assign an address to a farm.
```
curl -H "Key: <MYKEY>" -X POST http://<NFTLB IP>:5555/farms -d '{ "farms" : [ { "name" : "myfarm", "addresses" : [ { "name" : "myaddr" } ] } ] }'
```
Delete an address.
```
curl -H "Key: <MYKEY>" -X DELETE http://<NFTLB IP>:5555/addresses/myaddr
```
Delete an assigned address.
```
curl -H "Key: <MYKEY>" -X DELETE http://<NFTLB IP>:5555/farms/myfarm/addresses/myaddr
```
Delete an address.
```
curl -H "Key: <MYKEY>" -X DELETE http://<NFTLB IP>:5555/addresses/myaddr
```


## How it works

nftlb uses the nftables infrastructure to build virtual services, from user to kernel side. In that regard, the expressions **numgen** (with its **random** and **inc** modes) and **hash** (say **jhash** and **symhash**) allows to distribute traffic among several backends among other properties. More information:

[https://wiki.nftables.org/wiki-nftables/index.php/Load_balancing](https://wiki.nftables.org/wiki-nftables/index.php/Load_balancing)
[https://www.netfilter.org/projects/nftables/manpage.html](https://www.netfilter.org/projects/nftables/manpage.html)

This software creates the required tables named **nftlb** which are exclusive to the nftlb service and should not be managed manually. Ex: ip nftlb, ip6 nftlb, netdev nftlb...

The integration of nftlb with custom firewall rules are possible creating separated tables and playing with chain priorities. More information:

[https://www.zevenet.com/knowledge-base_category/nftlb/](https://www.zevenet.com/knowledge-base_category/nftlb/)

## Support
Please refer to the [netfilter users mailing list](http://netfilter.org/mailinglists.html#ml-user)
