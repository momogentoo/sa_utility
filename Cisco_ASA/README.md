# A Cisco ASA 5505 log parser

Introduction
================
Parse ASA 5505 syslog entries and display tcp/udp connections break-down by host 


How It Works
================
Parse the following events from ASA log entries -
# TCP
# %ASA-6-302013: Built outbound TCP connection 38627356 for outside:xxx.xx.xx.xxx/110 (xxx.xx.xx.xxx/110) to inside:aaa.bbb.ccc.ddd/53445 (aaa.bbb.ccc.ddd/38642)
# %ASA-6-302014: Teardown TCP connection 38627356 for outside:xxx.xx.xx.xxx/110 to inside:aaa.bbb.ccc.ddd/53445 duration 0:00:00 bytes 587 TCP FINs
# UDP 
# %ASA-6-302015: Built outbound UDP connection 38627355 for outside:xxx.xx.xx.xxx/53 (xxx.xx.xx.xxx/53) to inside:aaa.bbb.ccc.ddd/6129 (aaa.bbb.ccc.ddd/6129)
# %ASA-6-302016: Teardown UDP connection 38627355 for outside:xxx.xx.xx.xxx/53 to inside:aaa.bbb.ccc.ddd/6129 duration 0:00:00 bytes 148

And dynamically update a break-down list of TCP/UDP connections per host and output to screen

Usage
================
1. Configure ASA 5505 to send syslog and a syslogd daemon to receive logs. Preferred to redirect to a dedicate log file (like /var/log/asa.log). Refer to syslogd manual
2. Run "tail -F /var/log/asa.log | asa_realtime_mon.py"

Limitation
================
* Need a syslogd to receive log data from ASA
* Check Build/Tear-down TCP/UDP connection only

Sample Output
================
Last Update: Thu Dec  1 22:20:49 2016

Total TCP/UDP Connection: 27

Host                                           Total Connection            TCP                           UDP                      Max/Time

----------------------------------------------------------------------------------------------------------------------------------------------------------------

192.168.10.181                                  26(+5)                        25(+5)                         1                    30/Thu Dec  1 22:20:40 2016

192.168.10.182                                   1(-23)                        1(-22)                        0(-1)                64/Thu Dec  1 22:20:40 2016
