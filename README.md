# CS241 Report

### 0. Introduction

This report aims to explain critical design decisions in FILE **sniff.c**, **dispatch.c**, and **analysis.c**. Also, testing of the solution (SYN flooding attack, ARP cache poisoning attack, and blacklisted URL detection) is demonstrated.



### 1. sniff.c

##### 1.1 Continuous Capture of Packet

FUNCTION **pcap_loop()** is used to replace FUNCTION **pcap_next()**. To process packets from a live capture, the origin **pcap_next() **depends on a while-loop. However, **pcap_loop()** can be more effective to continuously sniff packets.

##### 1.2 Callback Function

A callback FUNCTION **handler()** is implemented. This callback function is called by FUNCTION **pcap_loop()** and then call FUNCTION **dispatch()**. The purpose is to prepare for the potential termination and handle it properly, as an intrusion report should anyway be printed when the program is killed.



### 2. dispatch.c

##### 2.1 Strategy of One-Thread-per-X Model

Creating a new thread for each unit of work (analysis) is utilised. A STRUCT **threadUnit** is created to apply this strategy, which meanwhile enables multithreading (pthreads) of checking. It is true that this model handles heavy or bursty load poorly, however, the resource management is difficult for the threadpool model. For example, once the pool is exhausted, a new thread will be delayed until older ones are finished, not to mention the code maintenance and readability. Therefore, for intermittent detecting of intrusion (which is the current case), One-Thread-per-X Model is more appropriate.

##### 2.2 POSIX Threads

Multithreading is achieved by implementing POSIX threads (pthread). FUNCTION **pthread_create()** is used to starts a new thread in the calling process. Besides, to respond the strategy of One-Thread-per-X-Model, a dynamic array of **threadUnit** is created by a callback function of **pthread_create()**.



### 3. analysis.c

#### 3.1 SYN Flooding Attack

##### 3.1.1 Detection

SYN information (including numbers of SYN packet and unique IP) is collected in FUNCTION **checkSYNAttack()**. For the SYN packet part, the function filters TCP SYN packets (as SYN bit is 1 while others are 0) and count the number. For the unique IP part, the function creates a dynamically growing array to store unique IP and count the number. To decide whether an IP is unique (has been stored before), FUNCTION **checkIPUniqueness()** is used, which loops the array trying to find the same one. If an IP has not been stored, it will be added into the array and then increment the unique IP counter.

##### 3.1.2 Testing

Command to send SYN packets:

```
hping3 -c 100 -d 120 -S -w 64 -p 80 -i u100 --rand-source localhost
```

The report will be formed:

```
100 SYN packets detected from 100 different IPs (syn attack)
0 ARP responses (cache poisoning)
0 URL Blacklist violations
```

To comprehensively test the code, all options including -c for amount of packet, -d for size of packet, -S for SYN flag, -w for TCP window size, -p for port, -i for interval, --rand-source for random source of IP are tested with different settings. For -d, -w, -p, -i, code is observed almost unaffected by these options. For -c, with the number increasing, it is more likely to encounter a "double free or corruption (out)" error. However, the program is stable as far as the number is within 700. This may due to a memory overflow when dealing with a burst of packets. 

For -S, with its removal, number of SYN packet and unique IP will be 0. It is expected as the program supposes to detect packet with a SYN flag bit of 1.

```
0 SYN packets detected from 0 different IPs (syn attack)
0 ARP responses (cache poisoning)
0 URL Blacklist violations
```

For --rand-source, with its removal, number of SYN packet remains intact but the amount of unique IP changes into 1. It is expected as this option generates random IP address. Without this option, there is only unique 1 IP address.

```
100 SYN packets detected from 1 different IPs (syn attack)
0 ARP responses (cache poisoning)
0 URL Blacklist violations
```

Also, the program can work properly when multiple times of the test command are given.

Therefore, the test can work correctly.



#### 3.2 ARP Cache Poisoning Attack

##### 3.2.1 Detection

ARP information (including number of ARP response) is collected in FUNCTION **checkARPAttack()**. To count ARP response, an ARP header is parsed and has operation code checked. If the operation code is "REPLY", it indicates an ARP response.

##### 3.2.2 Testing

Command to call a python script:

```
python3 arp-poison.py
```

The program works properly given this command, printing a report:

```
0 SYN packets detected from 0 different IPs (syn attack)
1 ARP responses (cache poisoning)
0 URL Blacklist violations
```

Also, the program can work properly when multiple times of the test command are given.

Therefore, the test can work correctly.



#### 3.3 Visiting Blacklisted URL

##### 3.3.1 Detection

IP information (including source IP address and destination IP address) is collected in FUNCTION **checkBlackList()**. To identify whether a visiting URL is blacklisted, packet's hostname is checked by FUNCTION **strstr()**. If the STRING **host** parsed from packet contains string of blacklisted URL (in this case "www.google.co.uk" and "www.bbc.com"), the counter is incremented and a notice will be given.

##### 3.3.2 Testing

Command to test:

```
wget www.google.co.uk
wget www.bbc.com
```

The program can successfully identify blacklisted URL:

```
==============================
Blacklisted URL violation detected
Source IP Address: 10
Destination IP Address: 64142
==============================

==============================
Blacklisted URL violation detected
Source IP Address: 10
Destination IP Address: 15060
==============================

^C
Intrusion Detection Report:
3 SYN packets detected from 1 different IPs (syn attack)
1 ARP responses (cache poisoning)
2 URL Blacklist violations
```

The program is unaffected by using **wget** command for other websites. Also, the program can work properly when multiple times of the test command are given.

Therefore, the test can work correctly.



##### 3.4 Management of Interrupt Signal

Interrupt signal is caught and then an intrusion report will be printed. To ensure a report will be formed if the program is killed by interrupt signal ("Ctrl+c"), CONDITION **signo == SIGINT** will be checked. If an interrupt signal is captured, intrusion report including information of SYN packets, ARP responses, and URL blacklist violations will be printed. Finally, to ensure a proper exit, **exit(0)** is used.
