# A Cisco ASA 5505 log parser

Introduction
================
Parse ASA 5505 syslog entries and display tcp/udp connections break-down by host 

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
