# Agartha { LFI | RCE | Auth | SQLi | Http-Js }
It is a burp extension for penetration testing and aimed to help researchers to find security issues. It creates dynamic word lists, access role matrix and more:
- **Payload Generator**: It creates payloads for different attacks.
	- **Local File Inclusion/Directory Traversal wordlist**: It creates dynamic dictionary list with various encoding and escaping characters.
	- **Remote Code Execution wordlist**: It creates dynamic dictionary list for both unix and windows enviorment with different combinations.
	- **SQL Injection wordlist**: It creates static boolean based SQLi dictionary list to help revealing vulnerable spots.
	- **Http Request to JavaScript Converter**: It converts Http requests to JavaScript code and might be useful for digging up XSS issues more.
- **Authorization Matrix**: It creates a authorization role matrix and helps to find user related auhtorization/authentication issues.

Here is a small tutorial how to use each feature.

## Local File Inclusion/Directory Traversal wordlist
It both supports unix and windows file systems. You can generate any wordlists for the path you want. You just need to supply a file name, and that's all. 

**'Dept'** is represantion of how deep the wordlist should be. You can generates word list 'till/equal to' this number.

**'Waf Bypass'** asks for if you want to include all bypass features, like null bytes, different encoding, etc.

<img width="900" alt="Local File Inclusion/Directory Traversal wordlist" src="https://user-images.githubusercontent.com/50321735/152035085-cc8ab660-d4d0-486a-9fda-8cb28b180e46.png">


## Remote Code Execution wordlist
It creates command exection word list for the command you supply. It combines different sepetator and terminator for unix and windows enviorments.

<img width="900" alt="Remote Code Execution wordlist" src="https://user-images.githubusercontent.com/50321735/152038242-a8163921-7147-41ba-9122-2e34244669dc.png">


## SQL Injection wordlist
It is for boolean based SQLi attacks and you dont need to supply any inputs. It generates static, vendor-neutral true and false criterias with escaping chacters and is appliaple for Mysql, Mssql, Oracle, Mariadb, PostgreSQL, etc. tests. 

<img width="900" alt="SQL Injection wordlist" src="https://user-images.githubusercontent.com/50321735/152039967-baa14153-f83c-49c3-9b51-d09a36027051.png">


## Http Request to JavaScript Converter
The feature is for converting Http requests to JavaScript language. It might be useful to dig up XSS issues and bypass header restrictions like CSP.

To access it, right click the Http request, extensions, agartha, copy as JavaScript.

<img width="900" alt="image" src="https://user-images.githubusercontent.com/50321735/152043556-490a7c02-2d07-443e-9cf4-267f68521c0d.png">

It will automaticly save it to your clipboard with some remarks. 
```
Http request in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm:80/dvwa/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');xhr.send('username=admin&password=pwd1234&Login=Login');</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};

To use in Developer Tools Console, you should remove 'script' tags.
```
