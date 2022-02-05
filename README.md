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

To access it, right click the Http Request, Extensions, 'Agartha', and 'Copy as JavaScript'.

<img width="1000" alt="Http Request to JavaScript Converter" src="https://user-images.githubusercontent.com/50321735/152224405-d10b78a2-9b18-44a9-a991-5b9c451c7253.png">

It will automaticly save it to your clipboard with some remarks. For example:
```
Http request with minimum header paramaters in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm:80/dvwa/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');xhr.send('username=admin&password=password&Login=Login');</script>

Http request with all header paramaters in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm:80/dvwa/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Host',' vm');xhr.setRequestHeader('User-Agent',' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0');xhr.setRequestHeader('Accept',' */*');xhr.setRequestHeader('Accept-Language',' en-US,en;q=0.5');xhr.setRequestHeader('Accept-Encoding',' gzip, deflate');xhr.setRequestHeader('Content-type',' application/x-www-form-urlencoded');xhr.setRequestHeader('Content-Length',' 44');xhr.setRequestHeader('Origin',' http://vm');xhr.setRequestHeader('Connection',' close');xhr.setRequestHeader('Referer',' http://vm/dvwa/login.php');xhr.setRequestHeader('Cookie',' security=high; PHPSESSID=1dab6afc3ced82d9828d008492bef43f');xhr.send('username=admin&password=password&Login=Login');</script>

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
4. All URLs you supply will be in here. Also user cell will be colored if it is in the user's list.
5. Http requests and responses wihout authentication. All session cookies and tokens will be removed form the calls.
6. Http requests and responses with the user session you created in the first step. Cell titles show Http response codes and response lenghts. 
7. Just click the cell you want to examine and Http details will be shown in here.


<img width="1000" alt="Role Matrix" src="https://user-images.githubusercontent.com/50321735/152227189-9e4b93df-de26-438e-ac1c-1aabcaf1ff56.png">


After clicking 'RUN', the tool will fill user and URL matrix with different colors. Besides the user colors, you will see orange, yellow and red cells.
- The cell is Yellow, because the response returns 'HTTP 302' with authentication/authorization concerns
- The cell is Orange, because the response returns 'HTTP 200' but different content length, with authentication/authorization concerns
- The cell is Red, because the response returns 'HTTP 200' and same content length, with authentication/authorization concerns

It will be quite similar, even if we add more users. Any authorization concerns will be highlighted.

You may also notice, it support only one http request method and header at the same time, because it processes bulk requests and it is not possible to provide different header options for each calls. But you change play with 'GET/POST' methods to see response differences.
