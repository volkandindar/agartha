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
It both supports unix and windows file systems. You can generate any wordlists for the path you want. You just need to supply a file path and that's all. 

**'Depth'** is represantion of how deep the wordlist should be. You can generates word list 'till/equal to' this value.

**'Waf Bypass'** asks for if you want to include all bypass features, like null bytes, different encoding, etc.

<img width="1000" alt="Directory Traversal/Local File Inclusion wordlist" src="https://user-images.githubusercontent.com/50321735/152050458-84c29e84-6e12-486b-99d2-fcf220791798.png">


## Remote Code Execution wordlist
It creates command exection word list for the command you supply. It combines different sepetator and terminator for unix and windows enviorments together.

<img width="1000" alt="Remote Code Execution wordlist" src="https://user-images.githubusercontent.com/50321735/152050785-82901333-b5e8-4e51-9467-adc2f6f0b628.png">


## SQL Injection wordlist
It is for boolean based SQLi attacks and you dont need to supply any inputs. It generates static, vendor-neutral true and false criterias with escaping chacters and  appliaple for Mysql, Mssql, Oracle, Mariadb, PostgreSQL, etc. 

<img width="1000" alt="SQL Injection wordlist" src="https://user-images.githubusercontent.com/50321735/152051426-d42cf034-3fe5-4221-9ec7-570c5f0249a8.png">


## Http Request to JavaScript Converter
The feature is for converting Http requests to JavaScript language. It can be useful to dig up XSS issues and bypass header restrictions, like CSP, CORS.

To access it, right click the Http request, extensions, 'Agartha', and 'Copy as JavaScript'.

<img width="1000" alt="Http Request to JavaScript Converter" src="https://user-images.githubusercontent.com/50321735/152224405-d10b78a2-9b18-44a9-a991-5b9c451c7253.png">

It will automaticly save it to your clipboard with some remarks. For example:
```
Http request in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm:80/dvwa/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');xhr.send('username=admin&password=pwd1234&Login=Login');</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};
```

## Authorization Matrix
It creates an access maxtrix based on user sessions/URL list, and helps to find authentication/authorization issues. You should first create a user with the followings:
- **User session name**: You can right click on any request and send it Agartha Panel.
- **URL list** user can visit: You can use Burp's spider or any sitemap generator. You need to put here all URLs the user can visit.

<img width="1000" alt="Authorization Matrix, sending http req" src="https://user-images.githubusercontent.com/50321735/152217672-353b42a8-bb06-4e92-b9af-3f4e487ab1fd.png">


After sending Http request to Agartha, it will fill some fields in the tool and wait for the next step. 
1. What's username for the session you provide. You can add up to 4 different users and each user will have a different color to make it easy to read.
2. User's request header. Session calls will be based on it.
3. URLs the user can visit. You can create this list with manual effort or automatic tools, like spiders, sitemap generators, etc.
4. All URLs together will be shown in here. It will be colored if the user provide the URL. It helps to figure out which one belongs to which user.
5. Http request and response wihout authentication. All session cookies or tokens will be removed form header.
6. You can see all Http response codes and response lenghts for the users created in the first step. 
7. Http request/response details can be examined here.


<img width="1000" alt="Role Matrix" src="https://user-images.githubusercontent.com/50321735/152227189-9e4b93df-de26-438e-ac1c-1aabcaf1ff56.png">


After clicking 'RUN', the tool will fill user and URL matrix with different colors. Besides the user colors, you will see orange, yellow and red cells. According to the example:
- The cell is Orange, because the response returns 'HTTP 200' without authentication
- The cell is Red, because the response returns 'HTTP 200' with same content without authentication

You may notice, it support only one http request method at the same time, because it processes bulk requests and it is not possible to provide different header options for each call. But you change play with 'GET/POST' methods to see response differences.
