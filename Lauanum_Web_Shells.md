vHosts needed for these questions:

- `status.inlanefreight.local`

IP:
10.129.42.197

---

### Question 1:
Establish a web shell session with the target using the concepts covered in this section.
Submit the full path of the directory you land in. (Format: c:\path\you\land\in)

Went to the URI `http://status.inlanefreight.local/`

Edited the aspx file for rev shell found in laudanum folder with my ip.

Uploaded it, and received the debug message:

    C:\inetpub\wwwroot\status.inlanefreight.local\files\shell.aspx
	 
Lets switch up the slashes for a URI, and then visit that link:

    http://status.inlanefreight.local/files/shell.aspx

We got a cmd exec web shell, baby!

run a quick DIR and the directory we land in is:

&#x1F6A9; **c:\windows\system32\inetsrv**

---

### Question 2:
Where is the Laudanum aspx web shell located on Pwnbox? Submit the full path. (Format: /path/to/laudanum/aspx)

&#x1F6A9; **/usr/share/laudanum/aspx/shell.aspx**
