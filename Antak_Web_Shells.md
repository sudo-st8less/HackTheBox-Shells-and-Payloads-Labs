### HTB Pentester Path <br>
### Shells & Payloads - Automating Payloads & Delivery with Metasploit Lab <br>
<mark>hook it up with a &#x2B50; if this helps.</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

vHosts needed for these questions:

- `status.inlanefreight.local`

---

IP:
10.129.42.197

---

### Question 1:
Where is the Antak webshell located on Pwnbox? Submit the full path. (Format:/path/to/antakwebshell)

&#x1F6A9; **/usr/share/nishang/Antak--edit--/antak.aspx**

---

### Question 2:
Establish a web shell with the target using the concepts covered in this section.
Submit the name of the user on the target that the commands are being issued as. In order to get the correct answer you must navigate to the web shell you upload using the vHost name. (Format: `****\****`, 1 space)

Go ahead and add IP + vhost to `/etc/hosts` file.

Browsed to `staus.inlanefreight.local` and uploaded the antak webshell found above, with altered creds, because responsibility. I renamed the file 'upload.aspx' to avoid detection, and I got the debug output:

Uploaded Configuration File Name: `C:\inetpub\wwwroot\status.inlanefreight.local\files\upload.aspx`

I navigated to this page with correct URI formatting on the slashes:

    http://status.inlanefreight.local//files/upload.aspx  

This gives us the the antek login page. After authenticating, just running a quick `whoami` gives us the user the commands are being issued as:

&#x1F6A9; **iis apppool\sta--edit--tus**
