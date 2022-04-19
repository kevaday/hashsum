import os

from PyQt5 import QtCore, QtGui, QtWidgets
from hashsum import DB_TYPES, ICON_FILENAME


class HashSumWindow(QtWidgets.QWidget):
    closing = QtCore.pyqtSignal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi()

    def setupUi(self):
        ...
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        self.setWindowIcon(QtGui.QIcon(ICON_FILENAME))
        self.setFixedSize(self.size())

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        self.closing.emit()
        a0.accept()


def show_dialog(txt: str, parent, title: str = None, error=False, modal=False):
    dialog = QtWidgets.QMessageBox(parent)
    dialog.setStandardButtons(QtWidgets.QMessageBox.Ok)
    dialog.setText(txt)
    dialog.setModal(modal)
    dialog.setWindowIcon(QtGui.QIcon(ICON_FILENAME))
    if error:
        dialog.setIcon(QtWidgets.QMessageBox.Critical)
    if not title:
        title = 'Dialog'
    dialog.setWindowTitle(title)
    dialog.show()


def file_dialog(parent):
    dialog = QtWidgets.QFileDialog(parent, directory=os.path.abspath(os.getcwd()))
    dialog.setFileMode(QtWidgets.QFileDialog.ExistingFile)
    dialog.setViewMode(QtWidgets.QFileDialog.Detail)
    dialog.setWindowIcon(QtGui.QIcon(ICON_FILENAME))
    if dialog.exec_() == QtWidgets.QFileDialog.Accepted:
        return dialog.selectedFiles()[0]


def file_or_folder_dialog(parent):
    dialog = QtWidgets.QFileDialog(parent, directory=os.path.abspath(os.getcwd()))
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setViewMode(QtWidgets.QFileDialog.Detail)
    dialog.setWindowIcon(QtGui.QIcon(ICON_FILENAME))
    if dialog.exec_() == QtWidgets.QFileDialog.Accepted:
        return dialog.selectedFiles()[0]


class CancelDialog(HashSumWindow):
    def __init__(self):
        super().__init__()

    def setupUi(self):
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)
        self.setObjectName("DialogMessage")
        self.resize(409, 142)
        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setGeometry(QtCore.QRect(10, 100, 381, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel)
        self.buttonBox.setObjectName("buttonBox")
        self.lblMsg = QtWidgets.QLabel(self)
        self.lblMsg.setGeometry(QtCore.QRect(30, 20, 351, 61))
        font = QtGui.QFont()
        font.setFamily("Trebuchet MS")
        font.setPointSize(16)
        self.lblMsg.setFont(font)
        self.lblMsg.setText("")
        self.lblMsg.setAlignment(QtCore.Qt.AlignCenter)
        self.lblMsg.setWordWrap(True)
        self.lblMsg.setObjectName("lblMsg")
        super().setupUi()


class ButtonBox(QtWidgets.QDialogButtonBox):
    def __init__(self, parent, *buttons):
        super().__init__(parent)
        self.setGeometry(QtCore.QRect(10, 100, 381, 32))
        self.setOrientation(QtCore.Qt.Horizontal)
        self.setStandardButtons(*buttons)
        self.setObjectName("buttonBox")


class Ui_DialogMessage(HashSumWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)

    def setupUi(self):
        self.setObjectName("DialogMessage")
        self.resize(409, 142)
        '''
        self.buttonBox = QtWidgets.QDialogButtonBox(DialogMessage)
        self.buttonBox.setGeometry(QtCore.QRect(10, 100, 381, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        '''
        self.lblMsg = QtWidgets.QLabel(self)
        self.lblMsg.setGeometry(QtCore.QRect(30, 20, 351, 61))
        font = QtGui.QFont()
        font.setFamily("Trebuchet MS")
        font.setPointSize(10)
        self.lblMsg.setFont(font)
        self.lblMsg.setText("")
        self.lblMsg.setAlignment(QtCore.Qt.AlignCenter)
        self.lblMsg.setWordWrap(True)
        self.lblMsg.setObjectName("lblMsg")

        self.retranslateUi(self)
        # self.buttonBox.accepted.connect(DialogMessage.accept)
        # QtCore.QMetaObject.connectSlotsByName(DialogMessage)
        super().setupUi()

    def retranslateUi(self, DialogMessage):
        _translate = QtCore.QCoreApplication.translate
        DialogMessage.setWindowTitle(_translate("DialogMessage", "Dialog"))


class Ui_MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi()

    def setupUi(self):
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        self.setWindowIcon(QtGui.QIcon(ICON_FILENAME))
        self.setObjectName("MainWindow")
        self.resize(800, 600)
        self.setFixedSize(self.size())

        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.lblTitle = QtWidgets.QLabel(self.centralwidget)
        self.lblTitle.setGeometry(QtCore.QRect(20, 10, 171, 51))
        font = QtGui.QFont()
        font.setPointSize(26)
        font.setBold(True)
        font.setWeight(75)
        self.lblTitle.setFont(font)
        self.lblTitle.setObjectName("lblTitle")
        self.lblSubtitle = QtWidgets.QLabel(self.centralwidget)
        self.lblSubtitle.setGeometry(QtCore.QRect(20, 60, 171, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        self.lblSubtitle.setFont(font)
        self.lblSubtitle.setObjectName("lblSubtitle")
        self.lblStatus = QtWidgets.QLabel(self.centralwidget)
        self.lblStatus.setGeometry(QtCore.QRect(410, 20, 240, 24))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblStatus.setFont(font)
        self.lblStatus.setWordWrap(False)
        self.lblStatus.setObjectName("lblStatus")
        self.lblScanned = QtWidgets.QLabel(self.centralwidget)
        self.lblScanned.setGeometry(QtCore.QRect(410, 60, 240, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblScanned.setFont(font)
        self.lblScanned.setWordWrap(False)
        self.lblScanned.setObjectName("lblScanned")
        self.lblThreats = QtWidgets.QLabel(self.centralwidget)
        self.lblThreats.setGeometry(QtCore.QRect(410, 80, 240, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblThreats.setFont(font)
        self.lblThreats.setWordWrap(False)
        self.lblThreats.setObjectName("lblThreats")
        self.lblTimeElapsed = QtWidgets.QLabel(self.centralwidget)
        self.lblTimeElapsed.setGeometry(QtCore.QRect(410, 100, 240, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblTimeElapsed.setFont(font)
        self.lblTimeElapsed.setWordWrap(False)
        self.lblTimeElapsed.setObjectName("lblTimeElapsed")
        self.lblTimeRemaining = QtWidgets.QLabel(self.centralwidget)
        self.lblTimeRemaining.setGeometry(QtCore.QRect(410, 120, 240, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblTimeRemaining.setFont(font)
        self.lblTimeRemaining.setWordWrap(False)
        self.lblTimeRemaining.setObjectName("lblTimeRemaining")
        self.lblFiles = QtWidgets.QLabel(self.centralwidget)
        self.lblFiles.setGeometry(QtCore.QRect(30, 170, 101, 21))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.lblFiles.setFont(font)
        self.lblFiles.setWordWrap(True)
        self.lblFiles.setObjectName("lblFiles")
        self.lblThreats_2 = QtWidgets.QLabel(self.centralwidget)
        self.lblThreats_2.setGeometry(QtCore.QRect(410, 170, 161, 21))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.lblThreats_2.setFont(font)
        self.lblThreats_2.setWordWrap(True)
        self.lblThreats_2.setObjectName("lblThreats_2")
        self.lstScanned = QtWidgets.QTableWidget(self.centralwidget)
        self.lstScanned.setGeometry(QtCore.QRect(20, 200, 371, 311))
        self.lstScanned.setColumnCount(2)
        self.lstScanned.setHorizontalHeaderLabels(['Path', 'Status'])
        self.lstScanned.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.lstScanned.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.lstScanned.setShowGrid(False)
        self.lstScanned.setObjectName("lstScanned")
        self.lstThreats = QtWidgets.QTableWidget(self.centralwidget)
        self.lstThreats.setGeometry(QtCore.QRect(410, 200, 361, 311))
        self.lstThreats.setColumnCount(2)
        self.lstThreats.setHorizontalHeaderLabels(['Path', 'Details'])
        self.lstThreats.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.lstThreats.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.lstThreats.setShowGrid(False)
        self.lstThreats.setObjectName("lstThreats")
        self.txtPath = QtWidgets.QLineEdit(self.centralwidget)
        self.txtPath.setGeometry(QtCore.QRect(20, 120, 231, 21))
        self.txtPath.setObjectName("txtPath")
        self.progressBar = QtWidgets.QProgressBar(self.centralwidget)
        self.progressBar.setGeometry(QtCore.QRect(20, 530, 751, 23))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.btnBrowse = QtWidgets.QPushButton(self.centralwidget)
        self.btnBrowse.setGeometry(QtCore.QRect(260, 120, 75, 23))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnBrowse.setFont(font)
        self.btnBrowse.setObjectName("btnBrowse")
        self.btnStartStop = QtWidgets.QPushButton(self.centralwidget)
        self.btnStartStop.setGeometry(QtCore.QRect(260, 30, 75, 51))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.btnStartStop.setFont(font)
        self.btnStartStop.setObjectName("btnStartStop")
        self.lblPath = QtWidgets.QLabel(self.centralwidget)
        self.lblPath.setGeometry(QtCore.QRect(20, 100, 171, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblPath.setFont(font)
        self.lblPath.setWordWrap(True)
        self.lblPath.setObjectName("lblPath")
        self.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(self)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName("menubar")
        self.menu_File = QtWidgets.QMenu(self.menubar)
        self.menu_File.setObjectName("menu_File")
        self.menu_Database = QtWidgets.QMenu(self.menubar)
        self.menu_Database.setObjectName("menu_Update")
        self.menu_Scan = QtWidgets.QMenu("&Scan", self.menubar)
        self.menu_Scan.setObjectName("menu_Scan")
        self.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.action_Exit = QtWidgets.QAction(self)
        self.action_Exit.setObjectName("action_Exit")
        self.action_DataSettings = QtWidgets.QAction(self)
        self.action_DataSettings.setObjectName("action_DataSettings")
        self.action_Settings = QtWidgets.QAction(self)
        self.action_Settings.setObjectName("action_Settings")
        self.action_SaveReport = QtWidgets.QAction(self)
        self.action_SaveReport.setObjectName("action_SaveReport")
        self.action_SaveReport = QtWidgets.QAction(self)
        self.action_About = QtWidgets.QAction(self)
        self.action_About.setObjectName("action_About")
        self.action_Update = QtWidgets.QAction(self)
        self.action_Update.setObjectName("action_Update")
        self.actionUnload = QtWidgets.QAction(self)
        self.actionUnload.setObjectName("action_Unload")
        self.actionLoad = QtWidgets.QAction(self)
        self.actionLoad.setObjectName("action_Load")
        self.menu_File.addAction(self.action_Settings)
        self.menu_File.addAction(self.action_SaveReport)
        self.menu_File.addAction(self.action_About)
        self.menu_File.addAction(self.action_Exit)
        self.menu_Database.addAction(self.actionLoad)
        self.menu_Database.addAction(self.actionUnload)
        self.menu_Database.addAction(self.action_Update)
        self.menu_Database.addAction(self.action_DataSettings)
        self.menubar.addAction(self.menu_File.menuAction())
        self.menubar.addAction(self.menu_Database.menuAction())

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "HashSum"))
        self.lblTitle.setText(_translate("MainWindow", "HashSum"))
        self.lblSubtitle.setText(_translate("MainWindow", "Simple Antivirus by Kevi Aday"))
        self.lblStatus.setText(_translate("MainWindow", "Ready"))
        self.lblScanned.setText(_translate("MainWindow", "Scanned:"))
        self.lblThreats.setText(_translate("MainWindow", "Suspicious Files: "))
        self.lblTimeElapsed.setText(_translate("MainWindow", "Time elapsed:"))
        self.lblTimeRemaining.setText(_translate("MainWindow", "Remaining: "))
        self.lblFiles.setText(_translate("MainWindow", "Scanned:"))
        self.lblThreats_2.setText(_translate("MainWindow", "Suspicious Files:"))
        self.btnBrowse.setText(_translate("MainWindow", "Browse"))
        self.btnStartStop.setText(_translate("MainWindow", "Start"))
        self.lblPath.setText(_translate("MainWindow", "Path to scan:"))
        self.menu_File.setTitle(_translate("MainWindow", "&File"))
        self.menu_Database.setTitle(_translate("MainWindow", "&Database"))
        self.action_Exit.setText(_translate("MainWindow", "&Exit"))
        self.action_DataSettings.setText(_translate("MainWindow", "&Settings"))
        self.action_Settings.setText(_translate("MainWindow", "&Settings"))
        self.action_SaveReport.setText(_translate("MainWindow", "Save Scan &Report"))
        self.action_About.setText(_translate("MainWindow", "&About"))
        self.action_Update.setText(_translate("MainWindow", "&Update"))
        self.actionUnload.setText(_translate("MainWindow", "Unload"))
        self.actionLoad.setText(_translate("MainWindow", "&Load"))


class Ui_FormMainSettings(HashSumWindow):
    def __init__(self):
        super().__init__()

    def setupUi(self):
        self.setObjectName("FormMainSettings")
        self.resize(410, 446)
        self.lblTitle = QtWidgets.QLabel(self)
        self.lblTitle.setGeometry(QtCore.QRect(100, 30, 191, 31))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblTitle.setFont(font)
        self.lblTitle.setWordWrap(True)
        self.lblTitle.setObjectName("lblTitle")
        self.lblWorkers = QtWidgets.QLabel(self)
        self.lblWorkers.setGeometry(QtCore.QRect(30, 190, 131, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblWorkers.setFont(font)
        self.lblWorkers.setWordWrap(True)
        self.lblWorkers.setObjectName("lblWorkers")
        self.lblFileChunksize = QtWidgets.QLabel(self)
        self.lblFileChunksize.setGeometry(QtCore.QRect(30, 230, 161, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblFileChunksize.setFont(font)
        self.lblFileChunksize.setWordWrap(True)
        self.lblFileChunksize.setObjectName("lblFileChunksize")
        self.lblLoadChunksize = QtWidgets.QLabel(self)
        self.lblLoadChunksize.setGeometry(QtCore.QRect(30, 300, 161, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblLoadChunksize.setFont(font)
        self.lblLoadChunksize.setWordWrap(True)
        self.lblLoadChunksize.setObjectName("lblLoadChunksize")
        self.numWorkers = QtWidgets.QSpinBox(self)
        self.numWorkers.setGeometry(QtCore.QRect(210, 190, 42, 22))
        self.numWorkers.setMinimum(1)
        self.numWorkers.setMaximum(16)
        self.numWorkers.setProperty("value", 2)
        self.numWorkers.setObjectName("numWorkers")
        self.numFileChunksize = QtWidgets.QSpinBox(self)
        self.numFileChunksize.setGeometry(QtCore.QRect(210, 250, 41, 22))
        self.numFileChunksize.setMinimum(0)
        self.numFileChunksize.setMaximum(9999)
        self.numFileChunksize.setProperty("value", 0)
        self.numFileChunksize.setObjectName("numFileChunksize")
        self.numLoadChunksize = QtWidgets.QSpinBox(self)
        self.numLoadChunksize.setGeometry(QtCore.QRect(210, 330, 101, 22))
        self.numLoadChunksize.setMaximum(999999)
        self.numLoadChunksize.setSingleStep(10)
        self.numLoadChunksize.setObjectName("numLoadChunksize")
        self.checkScanSubdirs = QtWidgets.QCheckBox(self)
        self.checkScanSubdirs.setGeometry(QtCore.QRect(30, 90, 161, 17))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.checkScanSubdirs.setFont(font)
        self.checkScanSubdirs.setChecked(True)
        self.checkScanSubdirs.setObjectName("checkScanSubdirs")
        self.btnReset = QtWidgets.QPushButton(self)
        self.btnReset.setGeometry(QtCore.QRect(80, 400, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnReset.setFont(font)
        self.btnReset.setObjectName("btnReset")
        self.btnBack = QtWidgets.QPushButton(self)
        self.btnBack.setGeometry(QtCore.QRect(210, 400, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnBack.setFont(font)
        self.btnBack.setObjectName("btnBack")
        self.checkScanArchives = QtWidgets.QCheckBox(self)
        self.checkScanArchives.setGeometry(QtCore.QRect(30, 110, 161, 17))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.checkScanArchives.setFont(font)
        self.checkScanArchives.setChecked(True)
        self.checkScanArchives.setObjectName("checkScanArchives")

        self.checkLoadWhileScanning = QtWidgets.QCheckBox(self)
        self.checkLoadWhileScanning.setGeometry(QtCore.QRect(30, 130, 280, 17))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.checkLoadWhileScanning.setFont(font)
        self.checkLoadWhileScanning.setChecked(True)
        self.checkLoadWhileScanning.setObjectName("checkLoadWhileScanning")

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)
        super().setupUi()

    def retranslateUi(self, FormMainSettings):
        _translate = QtCore.QCoreApplication.translate
        FormMainSettings.setWindowTitle(_translate("FormMainSettings", "HashSum - Settings"))
        self.lblTitle.setText(_translate("FormMainSettings", "HashSum Settings"))
        self.lblWorkers.setText(_translate("FormMainSettings", "Worker threads:"))
        self.lblFileChunksize.setText(_translate("FormMainSettings", "Thread chunk size "
                                                                     "(files per thread, 0 for auto):"))
        self.lblLoadChunksize.setText(_translate("FormMainSettings", "Load chunk size (KB per read, 0 for auto):"))
        self.btnReset.setText(_translate("FormMainSettings", "Reset Defaults"))
        self.btnBack.setText(_translate("FormMainSettings", "Back"))
        self.checkScanSubdirs.setText(_translate("FormMainSettings", "Scan subdirectories"))
        self.checkScanArchives.setText(_translate("FormMainSettings", "Scan archives"))
        self.checkLoadWhileScanning.setText(_translate("FormMainSettings", "Load dirs while scanning"))


class Ui_FormDatabaseSettings(HashSumWindow):
    def __init__(self):
        super().__init__()

    def setupUi(self):
        self.setObjectName("FormDatabaseSettings")
        self.resize(410, 491)
        self.lblTitle = QtWidgets.QLabel(self)
        self.lblTitle.setGeometry(QtCore.QRect(100, 10, 201, 31))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblTitle.setFont(font)
        self.lblTitle.setWordWrap(True)
        self.lblTitle.setObjectName("lblTitle")
        self.lblVersion = QtWidgets.QLabel(self)
        self.lblVersion.setGeometry(QtCore.QRect(100, 50, 191, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblVersion.setFont(font)
        self.lblVersion.setAlignment(QtCore.Qt.AlignCenter)
        self.lblVersion.setWordWrap(True)
        self.lblVersion.setObjectName("lblVersion")
        self.lblWorkers = QtWidgets.QLabel(self)
        self.lblWorkers.setGeometry(QtCore.QRect(30, 250, 131, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblWorkers.setFont(font)
        self.lblWorkers.setWordWrap(True)
        self.lblWorkers.setObjectName("lblWorkers")
        self.btnLoad = QtWidgets.QPushButton(self)
        self.btnLoad.setGeometry(QtCore.QRect(270, 200, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnLoad.setFont(font)
        self.btnLoad.setObjectName("btnLoad")
        self.btnLoadCustom = QtWidgets.QPushButton(self)
        self.btnLoadCustom.setGeometry(QtCore.QRect(270, 240, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnLoadCustom.setFont(font)
        self.btnLoadCustom.setObjectName("btnLoadCustom")
        self.lblSignatures = QtWidgets.QLabel(self)
        self.lblSignatures.setGeometry(QtCore.QRect(100, 70, 191, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblSignatures.setFont(font)
        self.lblSignatures.setAlignment(QtCore.Qt.AlignCenter)
        self.lblSignatures.setWordWrap(True)
        self.lblSignatures.setObjectName("lblSignatures")
        self.lblLoadChunksize = QtWidgets.QLabel(self)
        self.lblLoadChunksize.setGeometry(QtCore.QRect(30, 360, 131, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblLoadChunksize.setFont(font)
        self.lblLoadChunksize.setWordWrap(True)
        self.lblLoadChunksize.setObjectName("lblLoadChunksize")
        self.numWorkers = QtWidgets.QSpinBox(self)
        self.numWorkers.setGeometry(QtCore.QRect(180, 250, 42, 22))
        self.numWorkers.setMinimum(1)
        self.numWorkers.setMaximum(16)
        self.numWorkers.setProperty("value", 4)
        self.numWorkers.setObjectName("numWorkers")
        self.numLoadChunksize = QtWidgets.QSpinBox(self)
        self.numLoadChunksize.setGeometry(QtCore.QRect(180, 400, 101, 22))
        self.numLoadChunksize.setMaximum(999999)
        self.numLoadChunksize.setSingleStep(10)
        self.numLoadChunksize.setObjectName("numLoadChunksize")
        self.lblUpdateChunksize = QtWidgets.QLabel(self)
        self.lblUpdateChunksize.setGeometry(QtCore.QRect(30, 280, 141, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblUpdateChunksize.setFont(font)
        self.lblUpdateChunksize.setWordWrap(True)
        self.lblUpdateChunksize.setObjectName("lblUpdateChunksize")
        self.numUpdateChunksize = QtWidgets.QSpinBox(self)
        self.numUpdateChunksize.setGeometry(QtCore.QRect(180, 320, 41, 22))
        self.numUpdateChunksize.setMinimum(0)
        self.numUpdateChunksize.setMaximum(12)
        self.numUpdateChunksize.setProperty("value", 2)
        self.numUpdateChunksize.setObjectName("numUpdateChunksize")
        self.lblUpdate = QtWidgets.QLabel(self)
        self.lblUpdate.setGeometry(QtCore.QRect(100, 110, 191, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblUpdate.setFont(font)
        self.lblUpdate.setAlignment(QtCore.Qt.AlignCenter)
        self.lblUpdate.setWordWrap(True)
        self.lblUpdate.setObjectName("lblUpdate")
        self.lblLoaded = QtWidgets.QLabel(self)
        self.lblLoaded.setGeometry(QtCore.QRect(100, 90, 191, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblLoaded.setFont(font)
        self.lblLoaded.setAlignment(QtCore.Qt.AlignCenter)
        self.lblLoaded.setWordWrap(True)
        self.lblLoaded.setObjectName("lblLoaded")
        self.btnUpdate = QtWidgets.QPushButton(self)
        self.btnUpdate.setGeometry(QtCore.QRect(270, 160, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnUpdate.setFont(font)
        self.btnUpdate.setObjectName("btnUpdate")
        self.checkLoadOnStart = QtWidgets.QCheckBox(self)
        self.checkLoadOnStart.setGeometry(QtCore.QRect(30, 160, 161, 17))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.checkLoadOnStart.setFont(font)
        self.checkLoadOnStart.setChecked(True)
        self.checkLoadOnStart.setObjectName("checkLoadOnStart")
        self.btnReset = QtWidgets.QPushButton(self)
        self.btnReset.setGeometry(QtCore.QRect(80, 440, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnReset.setFont(font)
        self.btnReset.setObjectName("btnReset")
        self.btnBack = QtWidgets.QPushButton(self)
        self.btnBack.setGeometry(QtCore.QRect(210, 440, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.btnBack.setFont(font)
        self.btnBack.setObjectName("btnBack")
        self.checkUseGPU = QtWidgets.QCheckBox(self)
        self.checkUseGPU.setGeometry(QtCore.QRect(30, 200, 211, 17))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.checkUseGPU.setFont(font)
        self.checkUseGPU.setChecked(True)
        self.checkUseGPU.setObjectName("checkUseGPU")
        self.lblDatabaseType = QtWidgets.QLabel(self)
        self.lblDatabaseType.setGeometry(QtCore.QRect(260, 310, 131, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lblDatabaseType.setFont(font)
        self.lblDatabaseType.setWordWrap(True)
        self.lblDatabaseType.setObjectName("lblDatabaseType")
        self.comboDatabase = QtWidgets.QComboBox(self)
        self.comboDatabase.setGeometry(QtCore.QRect(260, 340, 131, 22))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.comboDatabase.setFont(font)
        self.comboDatabase.addItems(DB_TYPES)
        self.comboDatabase.setObjectName("comboDatabase")

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)
        super().setupUi()

    def retranslateUi(self, FormDatabaseSettings):
        _translate = QtCore.QCoreApplication.translate
        FormDatabaseSettings.setWindowTitle(_translate("FormDatabaseSettings", "HashSum - Database Settings"))
        self.lblTitle.setText(_translate("FormDatabaseSettings", "Database Settings"))
        self.lblVersion.setText(_translate("FormDatabaseSettings", "Signature Version: 0"))
        self.lblWorkers.setText(_translate("FormDatabaseSettings", "Worker threads:"))
        self.btnLoad.setText(_translate("FormDatabaseSettings", "Load Database"))
        self.btnLoadCustom.setText(_translate("FormDatabaseSettings", "Load File..."))
        self.lblSignatures.setText(_translate("FormDatabaseSettings", "Signatures: 0"))
        self.lblLoadChunksize.setText(_translate("FormDatabaseSettings", "Load chunksize (KB of data per read, 0 for "
                                                                         "auto):"))
        self.lblUpdateChunksize.setText(_translate("FormDatabaseSettings", "Update chunksize (signatures per thread):"))
        self.lblUpdate.setText(_translate("FormDatabaseSettings", "Update Available: False"))
        self.lblLoaded.setText(_translate("FormDatabaseSettings", "Database Loaded: False"))
        self.btnUpdate.setText(_translate("FormDatabaseSettings", "Update"))
        self.checkLoadOnStart.setText(_translate("FormDatabaseSettings", "Load on start"))
        self.btnReset.setText(_translate("FormDatabaseSettings", "Reset Defaults"))
        self.btnBack.setText(_translate("FormDatabaseSettings", "Back"))
        self.checkUseGPU.setText(_translate("FormDatabaseSettings", "Use GPU when applicable"))
        self.lblDatabaseType.setText(_translate("FormDatabaseSettings", "Database Type:"))


class Ui_FormAbout(HashSumWindow):
    def __init__(self):
        super().__init__()

    def setupUi(self):
        self.setObjectName("FormAbout")
        self.resize(494, 529)
        self.lblTitle = QtWidgets.QLabel(self)
        self.lblTitle.setGeometry(QtCore.QRect(130, 10, 191, 31))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblTitle.setFont(font)
        self.lblTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.lblTitle.setWordWrap(True)
        self.lblTitle.setObjectName("lblTitle")
        self.lblAbout = QtWidgets.QLabel(self)
        self.lblAbout.setGeometry(QtCore.QRect(20, 50, 451, 461))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblAbout.setFont(font)
        self.lblAbout.setAlignment(QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.lblAbout.setWordWrap(True)
        self.lblAbout.setObjectName("lblAbout")

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)
        super().setupUi()

    def retranslateUi(self, FormAbout):
        _translate = QtCore.QCoreApplication.translate
        FormAbout.setWindowTitle(_translate("FormAbout", "HashSum - About"))
        self.lblTitle.setText(_translate("FormAbout", "About"))
        self.lblAbout.setText(_translate("FormAbout",
                                         "<html><head/><body><p>HashSum is a tool developed by Kevi Aday to scan for "
                                         "potentially harmful files / malware. HashSum runs with a powerful "
                                         "multi-threaded scanning engine and has two options for the scanning "
                                         "database:</p><p>1. MD5 Hash:</p><p>Works by scanning files and calculating "
                                         "their MD5 hash. Then HashSum checks whether the MD5 exists in its database "
                                         "of known malicious MD5 hashes. The database is downloaded from the website "
                                         "VirusShare.com/hashes where millions of community-shared hash definitions "
                                         "exist for known malware samples. This database is updatable. This method "
                                         "for scanning is very fast, sometimes capable of scanning hundreds of files "
                                         "per second, but uses a lot of memory.</p><p>2. Deep Learning:</p><p>A deep "
                                         "learning artificial intelligence (more specifically a CNN called DenseNet) "
                                         "was trained on both malware and legitimate files and is capable of "
                                         "classifying files into 27 classes (one being legitimate files) to "
                                         "approximately 96% accuracy. This database is not updatable. This method for "
                                         "scanning is significantly slower than MD5 hashing (at approximately 10-20 "
                                         "files/second) but may be more accurate in detecting malware and uses a lot "
                                         "less memory (however it may be more resource-intensive).</p><p>Please keep "
                                         "in mind that threat detections may not always be accurate and for this "
                                         "reason HashSum does not delete files; it is merely a tool to find files "
                                         "that may be potentially harmful and is up to the user to take further "
                                         "actions.</p><p>If you encounter any problems, please contact "
                                         "kevaday@rogers.com. Happy scanning!</p></body></html>"))