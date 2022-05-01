from PyQt5 import QtGui, QtCore
from hashsum._gui import *
from hashsum import UPDATE_INTERVAL, SETTINGS_FILENAME, DEFAULT_SETTINGS
from hashsum import utils
from hashsum.database import Database, HashUpdate
from hashsum.scanning import Scanner

import json
import time
import os


class Settings(object):
    def update_gui(self):
        pass

    def update_settings(self):
        pass

    def reset_defaults(self):
        dialog = QtWidgets.QMessageBox(self)
        dialog.setIcon(QtWidgets.QMessageBox.Warning)
        result = dialog.question(self, 'Warning', 'Are you sure you want to reset settings to default? '
                                                  'All current settings will be overwritten.')
        if result == QtWidgets.QMessageBox.No:
            return

        self.settings = DEFAULT_SETTINGS
        self.update_gui()

    def back_clicked(self):
        self.update_settings()
        self.close()


class DataSettingsWindow(Ui_FormDatabaseSettings, Settings):
    gui_update = QtCore.pyqtSignal()
    
    def __init__(self, settings):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)
        self.settings = settings
        self.btnBack.clicked.connect(self.back_clicked)
        self.btnReset.clicked.connect(self.reset_defaults)
        self.update_gui()

    def update_gui(self):
        self.gui_update.emit()
        self.checkLoadOnStart.setChecked(self.settings['load_on_start'])
        self.numWorkers.setValue(self.settings['data_workers'])
        self.numUpdateChunksize.setValue(self.settings['update_chsz'])
        self.numLoadChunksize.setValue(self.settings['data_load_chsz']/1000)

    def update_settings(self):
        self.settings['load_on_start'] = self.checkLoadOnStart.isChecked()
        self.settings['data_workers'] = self.numWorkers.value()
        self.settings['update_chsz'] = self.numUpdateChunksize.value()
        self.settings['data_load_chsz'] = self.numLoadChunksize.value()*1000


class SettingsWindow(Ui_FormMainSettings, Settings):
    gui_update = QtCore.pyqtSignal()
    
    def __init__(self, settings):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)
        self.settings = settings
        self.btnBack.clicked.connect(self.back_clicked)
        self.btnReset.clicked.connect(self.reset_defaults)
        self.update_gui()

    def update_gui(self):
        self.gui_update.emit()
        self.checkScanSubdirs.setChecked(self.settings['scan_subdirs'])
        self.numWorkers.setValue(self.settings['scan_workers'])
        self.numFileChunksize.setValue(self.settings['scan_chsz'])
        self.numLoadChunksize.setValue(self.settings['scan_load_chsz']/1000)

    def update_settings(self):
        self.settings['scan_subdirs'] = self.checkScanSubdirs.isChecked()
        self.settings['scan_workers'] = self.numWorkers.value()
        self.settings['scan_chsz'] = self.numFileChunksize.value()
        self.settings['scan_load_chsz'] = self.numLoadChunksize.value()*1000


class MainWindow(Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.settings = {}
        self.generate_settings()
        self.load_settings()
        self.database = Database(load=False, on_load_fn=self.__on_load)
        self.scanner = Scanner(self.database)
        self.update_settings()
        self.win_settings = None
        self.win_data_settings = None
        self.win_about = Ui_FormAbout()
        self.dialog = None
        self.__update = None
        self.__timer = QtCore.QTimer(self)
        self.__timer.setInterval(UPDATE_INTERVAL)
        self.__timer.timeout.connect(self.__scan_update)
        self.__update_timer = QtCore.QTimer(self)
        self.__update_timer.setInterval(UPDATE_INTERVAL)
        self.__update_timer.timeout.connect(self.__check_update_done)
        self.action_Settings.triggered.connect(self.open_settings)
        self.action_About.triggered.connect(self.win_about.show)
        self.action_Exit.triggered.connect(self.close)
        self.actionLoad.triggered.connect(self.load_database)
        self.actionUnload.triggered.connect(self.database.clear)
        self.action_Update.triggered.connect(self.update_database)
        self.action_DataSettings.triggered.connect(self.open_data_settings)
        self.scan_running = False
        self.start_time = None
        self.btnStartStop.clicked.connect(self.start_scan)
        self.btnBrowse.clicked.connect(self.browse_scan_path)
        if self.settings['load_on_start']:
            self.load_database()

    def generate_settings(self):
        if os.path.exists(SETTINGS_FILENAME):
            return

        self.settings = DEFAULT_SETTINGS
        self.save_settings()

    def update_settings(self):
        self.database.chunksize = self.settings['data_load_chsz']
        self.database.update_obj.workers = self.settings['data_workers']
        self.database.update_obj.chunksize = self.settings['update_chsz']
        self.scanner.workers = self.settings['scan_workers']
        self.scanner.file_chunksize = self.settings['scan_chsz']
        self.scanner.load_chunksize = self.settings['scan_load_chsz']
        self.save_settings()

    def load_settings(self):
        with open(SETTINGS_FILENAME) as f:
            self.settings = json.load(f)

    def save_settings(self):
        with open(SETTINGS_FILENAME, 'w') as f:
            json.dump(self.settings, f)

    def load_database(self):
        self.dialog = CancelDialog()
        self.dialog.lblMsg.setText('Loading database...')
        self.dialog.setWindowTitle('Loading')
        del self.dialog.buttonBox
        self.dialog.show()
        try:
            self.database.clear()
            self.database.load(block=False)
        except (IOError, OSError, MemoryError) as e:
            self.dialog.close()
            show_dialog(f'Failed to load database. Error {e}', self, title='Error', error=True)

    def __on_load(self):
        self.dialog.close()
        if self.win_data_settings and self.win_data_settings.isVisible():
            self.win_data_settings.update_gui()

    def load_custom_database(self):
        file = file_dialog(self)
        if file:
            old_path = self.database.path
            self.database.path = file
            try:
                self.load_database()
            except (IOError, OSError, MemoryError) as e:
                self.database.path = old_path
                show_dialog(f'Failed to load database. Error {e}', self, title='Error', error=True)

    def __check_update_done(self):
        if self.__update.state == HashUpdate.STATE_IDLE:
            self.dialog.close()
            self.__update_timer.stop()
            show_dialog(f'Database updated. New version: {self.database.version}', self, title='Database Updated')

    def check_update(self) -> bool:
        return self.database.update_obj.check().available

    def update_database(self):
        self.__update = self.database.update_obj
        if not self.__update.check().available:
            show_dialog(f'Database up to date. Version {self.database.version}', self, title='Up to Date')
            return

        self.dialog = CancelDialog()
        self.dialog.lblMsg.setText('Updating database...')
        self.dialog.setWindowTitle('Updating')
        self.dialog.buttonBox.rejected.connect(self.__update.stop)
        self.dialog.show()
        self.database.clear()
        self.__update.apply_async(load_into_memory=False)
        self.__update_timer.start()

    def open_settings(self):
        self.win_settings = SettingsWindow(self.settings)
        self.win_settings.closing.connect(self.__settings_from_main)
        self.win_settings.show()

    def __settings_from_main(self):
        self.settings = self.win_settings.settings
        self.update_settings()

    def __settings_from_data(self):
        self.settings = self.win_data_settings.settings
        self.update_settings()

    def open_data_settings(self):
        self.win_data_settings = DataSettingsWindow(self.settings)
        self.win_data_settings.closing.connect(self.__settings_from_data)
        self.win_data_settings.btnLoad.clicked.connect(self.load_database)
        self.win_data_settings.btnLoadCustom.clicked.connect(self.load_custom_database)
        self.win_data_settings.btnUpdate.clicked.connect(self.update_database)
        self.win_data_settings.gui_update.connect(self.__update_data_labels)
        self.win_data_settings.show()

    def __update_data_labels(self):
        self.win_data_settings.lblSignatures.setText(f'Signatures: {self.database.signatures}')
        self.win_data_settings.lblVersion.setText(f'Version: {self.database.version}')
        self.win_data_settings.lblUpdate.setText(f'Update Available: {self.check_update()}')

    def browse_scan_path(self):
        path = file_or_folder_dialog(self)
        if path:
            self.txtPath.setText(path)

    def set_status(self, status: str):
        self.lblStatus.setText(status)

    def __get_files(self):
        pass

    def start_scan(self):
        if self.scan_running:
            self.finish_scan()
            return

        path = self.txtPath.text()
        if not os.path.exists(path):
            show_dialog('Invalid directory entered.', self, title='Error', error=True)
            return

        self.scan_running = True
        self.lstScanned.clear()
        self.lstThreats.clear()
        self.progressBar.reset()
        self.btnBrowse.setEnabled(False)
        self.btnStartStop.setText('Stop')
        '''
        self.btnStartStop.setEnabled(False)
        self.set_status('Preparing...')
        with ThreadPool(1) as self.__pool:
            result = self.__pool.apply_async(partial(utils.all_files, subdirs=self.settings['scan_subdirs']), args=(path,))
        self.files = list(utils.all_files(path, subdirs=self.settings['scan_subdirs']))
        '''
        self.btnStartStop.setEnabled(True)
        self.set_status('Scanning')
        self.start_time = time.time()
        self.scanner.scan_async(path, scan_subdirs=self.settings['scan_subdirs'])
        self.__timer.start()

    def __cont_start_scan(self):
        pass

    def finish_scan(self):
        self.__timer.stop()
        self.scanner.stop_scan_async(block=False)
        self.scan_running = False
        self.btnBrowse.setEnabled(True)
        self.btnStartStop.setText('Start')
        self.set_status('Ready')

    def __scan_update(self):
        scanned = len(self.scanner.files)
        total_files = len(self.scanner.all_files) - len(self.scanner.not_scanned)
        try:
            self.progressBar.setValue(scanned/total_files*100)
        except ZeroDivisionError:
            pass

        if self.scanner.state == Scanner.STATE_IDLE:
            self.finish_scan()

        self.lblScanned.setText(f'Scanned: {scanned}/{len(self.scanner.all_files)}')
        self.lblThreats.setText(f'Threats: {len(self.scanner.infected)}')
        self.lblTimeElapsed.setText(f'Time elapsed: {round(utils.timesince(self.start_time), 1)} s')
        self.lblTimeRemaining.setText(f'Remaining: {round(utils.estimate_time(total_files, scanned, self.start_time), 1)} s')
        font = QtGui.QFont()
        font.setFamily("Trebuchet MS")
        font.setPointSize(10)
        n_displayed = self.lstScanned.count()
        for path in self.scanner.files[n_displayed:]:
            item = QtWidgets.QListWidgetItem(path)
            item.setFont(font)
            self.lstScanned.addItem(item)
        n_displayed = self.lstThreats.count()
        for path in self.scanner.infected[n_displayed:]:
            item = QtWidgets.QListWidgetItem(path)
            item.setFont(font)
            self.lstThreats.addItem(item)
        self.lstScanned.scrollToBottom()
        self.lstThreats.scrollToBottom()

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        self.save_settings()
        a0.accept()


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
