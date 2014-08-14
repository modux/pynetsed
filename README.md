<h1>PyNetSed</h1>

<h2>Description</h2>

Python network find and replace tool for use on outbound or bridged (e.g. Man-in-the-Middle) connections.

TCP, UDP, ICMP

Uses Scapy and iptables with nfqueue

<h2>Installation</h2>

Tested and working on Linux Kali and Ubuntu

apt-get install scapy python-nfqueue

<h2>Usage</h2>

./netsed.py (-T,-U,-I) -p PORT [options] REPLACE_REGEX WITH_THIS

```
positional arguments:
  REGEX                 Regex expression to match
  NEW_VALUE             REPLACE VALUE

optional arguments:
  -h, --help            show this help message and exit
  -T, --tcp             Use protocol TCP
  -U, --udp             Use protocol UDP
  -I, --icmp            Use protocol ICMP
  -i eth1, --in-interface eth1
                        "In" interface
  -o eth0, --out-interface eth0
                        "Out" interface
  -r x.x.x.x, --remote-host x.x.x.x
                        IP address of remote host
  -p PORT, --port PORT  Traffic filter expression (tcpdump format)
  -f FLAGS, --regex-flags FLAGS
                        Regex Python flags, comma separated (e.g. I,U)
  -c FILE, --python-code FILE
                        Python module which contains a process function that
                        does processing
  -m MODE, --mode MODE  Mode to run the app in, use "br" or "out". br is used
                        in mitm, out is used for local outbound traffic
  -d DEBUG, --debug-interface DEBUG
                        Interface to send debug packets out of for monitoring
                        - 'lo' for loopback
  -t, --pass-through    When debugging performance, test the connection can be
                        passed through within modification

