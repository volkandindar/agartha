# Agartha - LFI, RCE, SQLi, Auth, HTTP to JS
Agartha is a penetration testing tool which creates dynamic payload lists and user access matrix to reveal injection flaws and authentication/authorization issues. There are many different attack payloads alredy exist, but Agartha creates run-time, systematic and vendor-neutral payloads with many different possibilities and bypassing methods. It also draws attention to user session and URL relationships, which makes easy to find user access violations. And additionally, it converts Http requests to JavaScript to help digging up XSS issues more. 


In summary:

- **Payload Generator**: It creates payloads/wordlists for different attack types.
	- **Local File Inclusion, Directory Traversal**: It creates file dictionary lists with various encoding and escaping characters.
	- **Command Injection / Remote Code Execution**: It creates command dictionary lists for both unix and windows environments with different combinations.
	- **SQL Injection**: It creates Stacked Queries, Boolean-Based, Union-Based and Time-Based SQL Injection wordlist for various databases to help finding vulnerable spots.
- **Authorization Matrix**: It creates an access matrix based on user sessions and URL lists, to determine authorization/authentication related violations. 
	- You can use **'SiteMap'** generator feature to create URL list. It will populate visible links automatically and the result will totally depend on the user's header.
- And **Copy as JavaScript**: It converts Http requests to JavaScript code for further XSS exploitation and more.<br/><br/>

Here is a small tutorial how to use.

## Installation
You should download 'Jython' file and set your environment first:
- Burp Menu > Extender > Options > Python Environment > Locate Jython standalone jar file (tested in Jython v2.7.3).

You can install Agartha through official store: 
- Burp Menu > Extender > BApp Store > Agartha

Or for manual installation:
- Burp Menu > Extender > Extensions > Add > Extension Type: Python > Extension file(.py): Select 'agartha.py' file

After all, you will see 'Agartha' tab in the main window and it will be also registered the right click, under: 
- 'Extensions > Agartha - LFI, RCE, SQLi, Auth, HTTP to JS', with two sub-menus
	- 'Authorization Matrix'
	- 'Copy as JavaScript'<br/><br/>

<!---## Tested in
- Jython version v2.7.3
- Burp Suite v2022.8.5<br/><br/>-->

## Local File Inclusion, Directory Traversal
It both supports unix and windows file syntax. You can generate any wordlists dynamically for the path you want. You just need to supply a file path and that's all. 

**'Depth'** is representation of how deep the wordlist should be. You can generate wordlists 'till' or 'equal to' this value.

**'Waf Bypass'** asks for if you want to include all bypass features; like null bytes, different encoding, etc.

<img width="1000" alt="Directory Traversal/Local File Inclusion wordlist" src="https://user-images.githubusercontent.com/50321735/195392551-f43be30a-5dc8-4337-bd49-2c3d65da325c.gif"><br/><br/>


## Command Injection / Remote Code Execution
It creates command execution dynamic wordlists with the command you supply. It combines different separators and terminators for both unix and windows environments together.

**'URL Encoding'** encodes dictionary output.

<img width="1000" alt="Remote Code Execution wordlist" src="https://user-images.githubusercontent.com/50321735/195392183-cea812d2-4301-4bf0-8d2a-43510c144a99.gif"><br/><br/>

## SQL Injection
It generates payloads for Stacked Queries, Boolean-Based, Union-Based, Time-Based SQL Injection attacks, and you do not need to supply any inputs. You just pick what type of SQL attacks and databases you want, then it will generate a wordlist with different combinations. 

**'URL Encoding'** encodes dictionary output.

**'Waf Bypass'** asks for if you want to include all bypass features; like null bytes, different encoding, etc.

**'Union-Based'** ask for how deep the payload should be. The default value is 5.

And the rest is related with databases and attack types.

<!---<img width="1000" alt="SQL Injection wordlist" src="https://user-images.githubusercontent.com/50321735/195392775-8f7a7ada-ed03-4024-b4fc-5d2783470bfb.gif">-->

<img width="1000" alt="SQL Injection wordlist" src="https://github.com/volkandindar/agartha/assets/50321735/b604c709-11a5-481c-b8b8-17868144ddcc"><br/><br/>


## Authorization Matrix / User Access Table
This part focuses on user session and URLs relationships to determine access violations. The tool will visit all URLs from pre-defined user sessions and fill the table with all Http responses. It is a kind of access matrix and helps to find out authentication/authorization issues. Afterwards you will see what users can access what page contents.
- **User session name**: You can right click on any request ('Extensions > Agartha > Authorization Matrix') to define a user session and name it.
- **URL Addresses** the user (Http header/session owner) can visit: You can use 'SiteMap' generator feature or supply any manual list. You need to provide visitable URL lists for all users.
- After providing session name, Http header and allowed URLs you can use 'Add User' button to add it.
<!--- <img width="1000" alt="Authorization Matrix" src="https://user-images.githubusercontent.com/50321735/195411200-d8728663-1735-4659-adf5-7276660d5afd.gif"> ---> 

<img width="1000" alt="Authorization Matrix" src="https://github.com/volkandindar/agartha/assets/50321735/d43f5bee-6eb3-4fda-9737-d8cdad293863">

A little bit more details:
1. What's username for the session you provide. You can add up to 4 different users and each user will have a different color to make it more readable.
	- 'Add User' for adding user session.
	- You can change Http request method between 'GET' and POST.
	- 'Reset' button clear all contents.
	- 'Run' button execute the task and the result will show user access matrix.
	- 'Warnings' indicates possible issues in different colors.
	- 'SiteMap' button generates URL list automatically and the result totally depends on the user's header you provide. Visible URLs will be populated in next textbox and you can still modify it.
	- 'Crawl Depth' is defination for how many sub-links (max depth) should 'SiteMap' spider go and detect links.
2. User's request header and all URLs will be visited over it.
3. URL addresses that user can visit. You can create this list with manual effort or use **'SiteMap'** generator feature.
4. All URLs you supply will be in here and they will be visited with the corresponding user sessions.
5. No authentication column. All cookies, tokens and possible session parameters will be removed form Http calls.
6. The rest of columns belong to users you created respectively and each of them has a unique color which indicates the URL owners.  
7. Cell titles show Http response codes and response lengths for each user sessions.
8. Just click the cell you want to examine and Http details will be shown in the bottom.

<!--- <img width="1000" alt="Matrix Details" src="https://user-images.githubusercontent.com/50321735/192441769-1632b642-2048-4b10-a91b-ae2c4db3d111.png"> ---> 

<img width="1000" alt="Matrix Details" src="https://github.com/volkandindar/agartha/assets/50321735/4418ad6f-cd24-425e-bd3b-00dfdfda8c4f">

After clicking 'RUN', the tool will fill user and URL matrix with different colors. Besides the user colors, you will see orange, yellow and red cells. The URL address does not belong to the user and the cell color is:
- Yellow, because the response returns 'HTTP 302' with authentication/authorization concerns
- Orange, because the response returns 'HTTP 200' but different content length, with authentication/authorization concerns
- Red, because the response returns 'HTTP 200' and same content length, with authentication/authorization concerns

You may also notice, it support only one Http request method and user session at the same time, because it processes bulk requests and it is not possible to provide different header options for each calls. But you may play with 'GET/POST' methods to see response differences.<br/><br/>


## Copy as JavaScript
The feature is for converting Http requests to JavaScript code. It can be useful to dig up further XSS issues and bypass header restrictions.

To access it, right click any Http Request and 'Extensions > Agartha > Copy as JavaScript'.

<!--- <img width="1000" alt="Copy as JavaScript" src="https://user-images.githubusercontent.com/50321735/152224405-d10b78a2-9b18-44a9-a991-5b9c451c7253.png"> ---> 

<img width="1000" alt="Copy as JavaScript" src="https://github.com/volkandindar/agartha/assets/50321735/4605b296-4c94-456c-b5b2-c8042a348cd2">

It will automatically save it to your clipboard with some remarks. For example:
```
Http request with minimum header paramaters in JavaScript:
	<script>var xhr=new XMLHttpRequest();
		xhr.open('GET','http://dvwa.local/vulnerabilities/xss_r/?name=XSS');
		xhr.withCredentials=true;
		xhr.send();
	</script>

Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:
	<script>var xhr=new XMLHttpRequest();
		xhr.open('GET','http://dvwa.local/vulnerabilities/xss_r/?name=XSS');
		xhr.withCredentials=true;xhr.setRequestHeader('Host',' dvwa.local');
		xhr.setRequestHeader('User-Agent',' Mozilla/5.0 Gecko/20100101 Firefox/114.0');
		xhr.setRequestHeader('Accept',' text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8');
		xhr.setRequestHeader('Accept-Language',' en-GB,en;q=0.5');
		xhr.setRequestHeader('Accept-Encoding',' gzip, deflate');
		xhr.setRequestHeader('Connection',' close');
		xhr.setRequestHeader('Referer',' http://dvwa.local/vulnerabilities/xss_r/');
		xhr.setRequestHeader('Upgrade-Insecure-Requests',' 1');
		xhr.send();
	</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};
```
Please note that, the JavaScript code will be called over original user session and many header fields will be filled automatically by browsers. In some cases, the server may require some header field mandatory, and therefore you may need to modify the code for an adjustment.
<br/><br/>
[Another tutorial link](https://www.linkedin.com/pulse/agartha-lfi-rce-auth-sqli-http-js-volkan-dindar)
