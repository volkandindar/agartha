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
The feature is for converting Http requests to JavaScript language. It can be useful to dig up XSS issues and bypass header restrictions, like CSP, CORS.

To access it, right click the Http request, extensions, agartha, copy as JavaScript.

<img width="1000" alt="Http Request to JavaScript Converter" src="https://user-images.githubusercontent.com/50321735/152051704-ef8f4a6e-2672-4611-bcfa-6bb50a104b68.png">

It will automaticly save it to your clipboard with some remarks. 
```
Http request in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm:80/dvwa/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');xhr.send('username=admin&password=pwd1234&Login=Login');</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};
```

## Authorization Matrix
It creates a access maxtrix based on user sessions and helps to find authentication/authorization issues. You should first create a user with the followings:
- **User session**: You can right click on any request and send it Agartha Panel.
- **URL list** user can visit: You can use Burp's spider or any sitemap generator. You need to put here all URLs the user can visit.

<img width="1000" alt="Authorization Matrix, sending http req" src="https://user-images.githubusercontent.com/50321735/152217672-353b42a8-bb06-4e92-b9af-3f4e487ab1fd.png">


After sending Http request to Agartha, it will fill some fields in the tool, but it is not enough to perform a proper role matrix. 
1. What's username for the session you provided.  
3. User's request header. Session URL calls will be based on this header.
4. URLs user can visit. You can create this list with manuel effort or automatic tools, like spiders, sitemap generators, etc.
5. All URLs together will be shown in here. It be colored if the user provided the URL. So you will understand which one belongs to which user.
6. Http request result wihout authentication. All session cookies or tokens will be removed form header.
7. You can add up to 4 different users and each user will have a different color to make it easy to read.
8. Http request and response can be examined here.

After clicking 'RUN', the tool will fill user and URL matrix with different colors. Besides the user colors, you will see orange, yellow and red cells. According to the example which is shown below:
- Orange cell means, the response returns 'HTTP 200' without authentication
- Red cell means, the response returns 'HTTP 200' with same content without authentication
You can see all Http response code and response lenght in the matrix.
<img width="1000" alt="Role Matrix" src="https://user-images.githubusercontent.com/50321735/152223013-65628eb8-94ec-40ea-a523-a4cb8d42359f.png">

You may notice, it support only one http request method at the same time, because it processes bulk requests and it is not possible to provide different header options for each call. But you change play with 'GET/POST' methods to see response differences.
