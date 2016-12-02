# A Cisco ASA 5505 log parser

Introduction
================
Parse ASA 5505 syslog entries and display tcp/udp connections break-down by host 


Sample Output
================
Last Update: Thu Dec  1 22:20:49 2016
Total TCP/UDP Connection: 27

Host                                           Total Connection            TCP                           UDP                      Max/Time
----------------------------------------------------------------------------------------------------------------------------------------------------------------
192.168.10.181                                  26(<span style="color:green;">+5</span>)                        25(<span style="color:green;">+5</span>)                         1                    30/Thu Dec  1 22:20:40 2016
192.168.10.182                                   1(<span style="color:red;">-23</span>)                        1(<span style="color:red;">-22</span>)                        0(<span style="color:red;">-1</span>)                64/Thu Dec  1 22:20:40 2016
