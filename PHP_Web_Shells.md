### HTB Pentester Path <br>
### Shells & Payloads - PHP Web Shells Lab <br>
<mark>hook it up with a &#x2B50; if this helps.</mark> <br>
🐦: @<a href="https://x.com/st8less">**st8less**</a>
<br>

---

IP:
10.129.201.101

---

### Question 1:
In the example shown, what must the Content-Type be changed to in order to successfully upload the web shell? (Format: .../... )

&#x1F6A9; **image/gif**

---

### Question 2:
Use what you learned from the module to gain a web shell. What is the file name of the gif in the /images/vendor directory on the target? (Format: xxxx.gif)
WWW
Navigated to http://10.129.201.101/login.php

Auth'd with default creds `admin:admin`.

Went to Devices>Vendors>Add Vendor 

Created local file on pwnbox with WWW's php shell, and named it `splooge.php`. Removed Comments and identifiers for evasion purposes.

Set FoxyProxy extension to BURP, and opened burpsuite.

In burp suite, hit the Proxy tab, and make sure Intercept is on. Now execute the upload on the website. We're looking for a POST request in Burp, which happens to be the first one I got.

We're going to change the `Content-Type` field from `application/x-php` to `image/gif`. Make sure you are editing the correct `Content-Type`, as there is one in the header that suggests 'multipart' and another below that gives the application parameter. You want the one below. Now forward the POST and the following GET request, which will display the php shell in the browser.

Blast off a quick `ls` to see the images uploaded to the server:

	ajax-loader.gif
	cisco.jpg
	juniper.jpg
	splooge.php

&#x1F6A9; found **ajax-load--edit--er.gif**

