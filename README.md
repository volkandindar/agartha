# Agartha { LFI | RCE | Auth | SQLi | Http-Js }
It is a burp extension for penetration testing and aimed to help researchers to find security issues. It creates dynamic word lists, access role matrix and more:
- **Payload Generator**: It creates payloads for different attacks.
	- **Directory Traversal/Local File Inclusion wordlist**: It creates dynamic dictionary list with various encoding and escaping characters.
	- **Remote Code Execution wordlist**: It creates dynamic dictionary list for both unix and windows enviorment with different combinations.
	- **SQL Injection wordlist**: It creates static boolean based SQLi dictionary list to help revealing vulnerable spots.
	- **Http Request to JavaScript Converter**: It converts Http requests to JavaScript code and might be useful for digging up XSS issues more.
- **Authorization Matrix**: It creates a authorization role matrix and helps to find user related auhtorization/authentication issues.

Here is a small tutorial how to use each features.

## Directory Traversal/Local File Inclusion wordlist
It both supports unix and windows file systems. You can generate any wordlists for the path you want. You just need to supply a file name, and that's all. 

**'Depth'** is represantion of how deep the wordlist should be. You can generates word list 'till/equal to' this value.

**'Waf Bypass'** asks for if you want to include all bypass features, like null bytes, different encoding, etc.

<img width="1000" alt="Directory Traversal/Local File Inclusion wordlist" src="https://user-images.githubusercontent.com/50321735/152050458-84c29e84-6e12-486b-99d2-fcf220791798.png">


## Remote Code Execution wordlist
It creates command exection word list for the command you supply. It combines different sepetator and terminator for unix and windows enviorments together.

<img width="1000" alt="Remote Code Execution wordlist" src="https://user-images.githubusercontent.com/50321735/152050785-82901333-b5e8-4e51-9467-adc2f6f0b628.png">


## SQL Injection wordlist
It is for boolean based SQLi attacks and you dont need to supply any inputs. It generates static, vendor-neutral true and false criterias with escaping chacters and is appliaple for Mysql, Mssql, Oracle, Mariadb, PostgreSQL, etc. 

<img width="1000" alt="SQL Injection wordlist" src="https://user-images.githubusercontent.com/50321735/152051426-d42cf034-3fe5-4221-9ec7-570c5f0249a8.png">


## Http Request to JavaScript Converter
The feature is for converting Http requests to JavaScript language. It might be useful to dig up XSS issues and bypass header restrictions like CSP.

To access it, right click the Http request, extensions, agartha, copy as JavaScript.

<img width="1000" alt="Http Request to JavaScript Converter" src="https://user-images.githubusercontent.com/50321735/152051704-ef8f4a6e-2672-4611-bcfa-6bb50a104b68.png">

It will automaticly save it to your clipboard with some remarks. 
```
Http request in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm:80/dvwa/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');xhr.send('username=admin&password=pwd1234&Login=Login');</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};

To use in Developer Tools Console, you should remove 'script' tags.
```
