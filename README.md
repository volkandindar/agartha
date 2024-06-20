# Agartha - LFI, RCE, SQLi, Auth, 403 Bypass, HTTP to JS
Agartha, specializes in dynamic payload analysis and access control assessment. It adeptly identifies vulnerabilities related to injection attacks, user access matrix, and authentication/authorization issues. The dynamic payload generator crafts extensive wordlists for various injection vectors, including SQL Injection, Local File Inclusion  (LFI), and Remote Code Execution. Furthermore, Agartha constructs a comprehensive user access matrix, revealing potential access violations and privilege escalation paths. It also assists in performing HTTP 403 bypass checks, shedding light on authorization weaknesses. Additionally, it can convert HTTP requests to JavaScript code to help digging up XSS issues more.

In summary:

- **Payload Generator**: It dynamically constructs comprehensive wordlists for injection attacks, incorporating various encoding and escaping characters. These wordlists cover critical vulnerabilities such as SQL Injection, Local File Inclusion (LFI), and Remote Code Execution, making them indispensable for robust security testing.
	- **Local File Inclusion, Path Traversal**
	- **Command Injection, Remote Code Execution**
	- **SQL Injection**
- **Auth Matrix**: By constructing a comprehensive access matrix, the tool reveals potential access violations and privilege escalation paths. This feature enhances security posture by addressing authentication and authorization issues. 
	- You can use **'SiteMap'** generator feature to create URL list. It will populate visible links automatically and the result will totally depend on the user's header.
- **403 Bypass**: It tackles the common 403 Forbidden error. It employs techniques like URL manipulation and request header modification to bypass access restrictions.
- And **Copy as JavaScript**: It converts Http requests to JavaScript code for further XSS exploitation and more.<br/><br/>

Here is a small tutorial how to use.

## Installation
You should download 'Jython' file and set your environment first:
- Burp Menu > Extender > Options > Python Environment > Locate Jython standalone jar file (tested in Jython v2.7.3).

You can install Agartha through official store: 
- Burp Menu > Extender > BApp Store > Agartha

Or for manual installation:
- Burp Menu > Extender > Extensions > Add > Extension Type: Python > Extension file(.py): Select 'Agartha.py' file

After all, you will see 'Agartha' tab in the main window and it will be also registered the right click, under: 
- 'Extensions > Agartha - LFI, RCE, SQLi, Auth, HTTP to JS', with two sub-menus
	- 'Authorization Matrix'
	- 'Copy as JavaScript'<br/><br/>


## Local File Inclusion / Path Traversal
It supports both Unix and Windows file syntaxes, enabling dynamic wordlist generation for any desired path. Additionally, it can attempt to bypass Web Application Firewall (WAF) implementations, with various encodings and other techniques.
- **'Depth'** is representation of how deep the wordlist should be. You can generate wordlists 'till' or 'equal to' this value.
- **'Waf Bypass'** asks for if you want to include all bypass features; like null bytes, different encoding, etc.

<img width="1000" alt="Directory Traversal/Local File Inclusion wordlist" src="https://github.com/volkandindar/agartha/assets/50321735/b457e6c2-0829-4959-84aa-9116886b99f7"><br/><br/>



## Command Injection / Remote Code Execution
It generates dynamic wordlists for command execution based on the supplied command. It combines various separators and terminators for both Unix and Windows environments.
- **'URL Encoding'** encodes dictionary output.

<img width="1000" alt="Remote Code Execution wordlist" src="https://github.com/volkandindar/agartha/assets/50321735/d28c12c9-c6fb-4509-9299-888f3f048c12"><br/><br/>

## SQL Injection
It generates payloads for various types of SQL injection attacks, including Stacked Queries, Boolean-Based, Union-Based, and Time-Based. It doesn’t require any user inputs; you simply select the desired SQL attack types and databases, and it generates a wordlist with different combinations.
- **'URL Encoding'** encodes dictionary output.
- **'Waf Bypass'** asks for if you want to include all bypass features; like null bytes, different encoding, etc.
- **'Union-Based'** ask for how deep the payload should be. The default value is 5.
- And the rest is related with databases and attack types.

<img width="1000" alt="SQL Injection wordlist" src="https://github.com/volkandindar/agartha/assets/50321735/51a010b6-4d9a-4dc9-a634-b353f6b30b95"><br/><br/>

## Authorization Matrix / User Access Table
This part focuses on analyzing user session and URL relationships to identify access violations. The tool systematically visits all URLs associated with pre-defined user sessions and populates a table with HTTP responses. Essentially, it creates an access matrix, which aids in identifying authentication and authorization issues. Ultimately, this process reveals which users can access specific page contents.
- You can right click on any request ('Extensions > Agartha > Authorization Matrix') to define **user sessions**.
- Next, you need to provide **URL addresses** the user (Http header/session owner) can visit. You can use internal 'SiteMap' generator feature or supply any manual list. 
- And then, you can use **'Add User'** button to add the user sessions.
- Now, it is ready for execution with only clicking **'Run'** button, and it will fill the table. 

<img width="1000" alt="Authorization Matrix" src="https://github.com/volkandindar/agartha/assets/50321735/d43f5bee-6eb3-4fda-9737-d8cdad293863">

A little bit more details:
1. What's username for the session you provide. You can add up to 4 different users and each user will have a different color to make it more readable.
	- 'Add User' for adding user sessions to matrix.
	- You can change Http request method between 'GET', 'POST' or 'Dynamic', which bases on proxy history.
	- 'Reset' button clear all contents.
	- 'Run' button execute the task and the result will show user access matrix.
	- 'Warnings' indicates possible issues in different colors.
	- 'SiteMap' button generates URL list automatically and the result totally depends on the user's header/session. Visible URLs will be populated in next textbox and you can still modify it.
	- 'Crawl Depth' is defination for how many sub-links (max depth) 'SiteMap' spider should go and detect links.
2. It is the field for request headers and all URLs will be visited over the session defined in here.
3. URL addresses that user can visit. You can create this list with manual effort or use **'SiteMap'** generator feature. You need to provide visitable URL lists for each users.
4. All URLs you supply will be in here and they will be visited with the corresponding user sessions.
5. No authentication column. All cookies, tokens and possible session parameters will be removed form Http calls.
6. The rest of columns belong to users you created respectively and each of them has a unique color which indicates the URL owners.  
7. Cell titles show Http 'response codes:response lengths' for each user sessions.
8. Just click the cell you want to examine and Http details will be shown in the bottom.

<img width="1000" alt="User Access Table Details" src="https://github.com/volkandindar/agartha/assets/50321735/4418ad6f-cd24-425e-bd3b-00dfdfda8c4f">

After clicking 'RUN', the tool will fill user and URL matrix with different colors. Besides the user colors, you will see orange, yellow and red cells. The URL address does not belong to the user, and if the cell color is:
- **Red**, because the response returns 'HTTP 200' and same content length, with authentication/authorization concerns
- **Orange**, because the response returns 'HTTP 200' but different content length, with authentication/authorization concerns
- **Yellow**, because the response returns 'HTTP 302' with authentication/authorization concerns

The task at hand involves a bulk process, and it is worth to mention which HTTP request methods will be used. The tool provides three different options for performing HTTP calls:
- **GET**, All requests are sent using the GET method.
- **POST**, All requests are sent using the POST method.
- **Dynamic**, The request method depends on the proxy history.<br/><br/>

## 403 Bypass
{TO DO}


## Copy as JavaScript
The feature allows for converting HTTP requests to JavaScript code, which can be valuable for digging up further XSS issues and bypassing header restrictions.

To access it, right click any Http request and 'Extensions > Agartha > Copy as JavaScript'.

<img width="1000" alt="Copy as JavaScript" src="https://github.com/volkandindar/agartha/assets/50321735/771fd1db-c2ba-4a32-8b17-ef5cc53fa5bd">

It will automatically save it to your clipboard with some remarks. For example:
```
Http request with minimum header paramaters in JavaScript:
	<script>
		var xhr=new XMLHttpRequest();
		xhr.open('GET','http://dvwa.local/vulnerabilities/xss_r/?name=XSS');
		xhr.withCredentials=true;
		xhr.send();
	</script>

Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:
	<script>
		var xhr=new XMLHttpRequest();
		xhr.open('GET','http://dvwa.local/vulnerabilities/xss_r/?name=XSS');
		xhr.withCredentials=true;
		xhr.setRequestHeader('Host',' dvwa.local');
		xhr.setRequestHeader('User-Agent',' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0');
		xhr.setRequestHeader('Accept',' text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8');
		xhr.setRequestHeader('Accept-Language',' en-US,en;q=0.5');
		xhr.setRequestHeader('Accept-Encoding',' gzip, deflate, br');
		xhr.setRequestHeader('DNT',' 1');
		xhr.setRequestHeader('Sec-GPC',' 1');
		xhr.setRequestHeader('Connection',' keep-alive');
		xhr.setRequestHeader('Referer',' http://dvwa.local/vulnerabilities/xss_r/');
		xhr.setRequestHeader('Upgrade-Insecure-Requests',' 1');
		xhr.setRequestHeader('Priority',' u=1');
		xhr.send();
	</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};
```
Please note that the JavaScript code will be executed within the original user session, and many header fields will be automatically populated by browsers. In certain cases, the server may require specific header fields to be mandatory; for instance, some requests might fail with an incorrect ‘Content-Type’. Therefore, you may need to adjust the code accordingly.
<br/><br/>
[Another tutorial link](https://www.linkedin.com/pulse/agartha-lfi-rce-auth-sqli-http-js-volkan-dindar)
