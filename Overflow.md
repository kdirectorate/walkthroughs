# Overflow (Hack The Box)

![](./images/overflow/pwned.png)

In this box we take advantage of a SETUID binary via a buffer overflow and that's just the ending to this encryption and adrenalin filled twisty box.

## nmap

We'll start in the usual way. I utilize [AutoRecon](https://github.com/Tib3rius/AutoRecon) to run nmap and do the initial recon on a device. Its super noisy so I wouldn't suggest using it on a real target.

```
Nmap scan report for overflow.htb (10.10.11.119)
Host is up, received user-set (0.056s latency).
rDNS record for 10.10.11.119: overflow
Scanned at 2022-02-04 14:06:12 CST for 96s
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
25/tcp open  smtp    syn-ack Postfix smtpd
|_smtp-commands: overflow, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Overflow Sec
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host:  overflow; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

