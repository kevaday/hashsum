from copy import deepcopy
from functools import partial

from PyQt5 import QtGui, QtCore

from hashsum._gui import *
from hashsum import UPDATE_INTERVAL, SETTINGS_FILENAME, DEFAULT_SETTINGS, DB_TYPE_HASH, DB_TYPE_AI, DB_TYPE_DUMMY, \
    SCAN_PATH_WILDCARD
from hashsum import utils
from hashsum.database import HashDatabase, NNDatabase, BaseDatabase, HashUpdate, LoadError
from hashsum.scanning import Scanner, SCAN_TYPES, ScanQuery

import json
import time
import os


class Settings:
    def update_gui(self):
        pass

    def update_settings(self):
        pass

    def reset_defaults(self):
        dialog = QtWidgets.QMessageBox(self)
        dialog.setIcon(QtWidgets.QMessageBox.Warning)
        if dialog.question(self, 'Warning', 'Are you sure you want to reset settings to default? '
                                            'All current settings will be overwritten.') \
            == QtWidgets.QMessageBox.No: return

        self.settings = DEFAULT_SETTINGS
        self.update_gui()


class DataSettingsWindow(Ui_FormDatabaseSettings, Settings):
    gui_update = QtCore.pyqtSignal()

    def __init__(self, settings):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        self.settings = settings
        self.btnBack.clicked.connect(self.close)
        self.btnReset.clicked.connect(self.reset_defaults)

    def update_gui(self):
        self.gui_update.emit()
        self.update()
        self.checkLoadOnStart.setChecked(self.settings['load_on_start'])
        self.checkUseGPU.setChecked(self.settings['use_gpu'])
        self.comboDatabase.setCurrentIndex(DB_TYPES.index(self.settings['database_type']))
        self.numWorkers.setValue(self.settings['scan_workers'])
        self.numUpdateChunksize.setValue(self.settings['update_chsz'])
        self.numLoadChunksize.setValue(self.settings['data_load_chsz'] / 1000)

    def update_settings(self):
        self.settings['load_on_start'] = self.checkLoadOnStart.isChecked()
        self.settings['use_gpu'] = self.checkUseGPU.isChecked()
        self.settings['database_type'] = self.comboDatabase.currentText()
        self.settings['data_workers'] = self.numWorkers.value()
        self.settings['update_chsz'] = self.numUpdateChunksize.value()
        self.settings['data_load_chsz'] = self.numLoadChunksize.value() * 1000

    def closeEvent(self, event: QtGui.QCloseEvent):
        self.update_settings()
        event.accept()


class SettingsWindow(Ui_FormMainSettings, Settings):
    gui_update = QtCore.pyqtSignal()

    def __init__(self, settings):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        self.settings = settings
        self.btnBack.clicked.connect(self.close)
        self.btnReset.clicked.connect(self.reset_defaults)

    def update_gui(self):
        self.gui_update.emit()
        self.update()
        self.checkScanSubdirs.setChecked(self.settings['scan_subdirs'])
        self.checkScanArchives.setChecked(self.settings['scan_archives'])
        self.checkLoadWhileScanning.setChecked(self.settings['load_while_scanning'])
        self.numFileChunksize.setValue(self.settings['scan_chsz'])
        self.numWorkers.setValue(self.settings['data_workers'])
        self.numLoadChunksize.setValue(self.settings['scan_load_chsz'])

    def update_settings(self):
        self.settings['scan_subdirs'] = self.checkScanSubdirs.isChecked()
        self.settings['scan_archives'] = self.checkScanArchives.isChecked()
        self.settings['load_while_scanning'] = self.checkLoadWhileScanning.isChecked()
        self.settings['scan_chsz'] = self.numFileChunksize.value()
        self.settings['scan_workers'] = self.numWorkers.value()
        self.settings['scan_load_chsz'] = self.numLoadChunksize.value() * 1000

    def closeEvent(self, event: QtGui.QCloseEvent):
        self.update_settings()
        event.accept()


class MainWindow(Ui_MainWindow):
    def __init__(self):
        super().__init__()

        for menu_name, func_info in SCAN_TYPES.items():
            action = QtWidgets.QAction('&' + menu_name, self)
            action.setObjectName(menu_name)
            action.triggered.connect(partial(self.__scan_func_wrapper, func=func_info[0], func_args=func_info[1:]))
            self.menu_Scan.addAction(action)
        self.menubar.addAction(self.menu_Scan.menuAction())

        self.settings = DEFAULT_SETTINGS
        self.generate_settings()
        self.load_settings()
        self.database = None
        self.scanner = None
        self._old_db_type = None
        self.update_settings()
        self.win_settings = None
        self.win_data_settings = None

        self.win_about = Ui_FormAbout()
        self.dialog = None
        self.__update = None

        self.__load_timer = QtCore.QTimer(self)
        self.__load_timer.setInterval(UPDATE_INTERVAL)
        self.__load_timer.timeout.connect(self.__check_load_done)
        self.__scan_timer = QtCore.QTimer(self)
        self.__scan_timer.setInterval(UPDATE_INTERVAL)
        self.__scan_timer.timeout.connect(self.__scan_update)
        self.__update_timer = QtCore.QTimer(self)
        self.__update_timer.setInterval(UPDATE_INTERVAL)
        self.__update_timer.timeout.connect(self.__check_update_done)

        self.action_Settings.triggered.connect(self.open_settings)
        self.action_About.triggered.connect(self.win_about.show)
        self.action_Exit.triggered.connect(self.close)
        self.actionLoad.triggered.connect(self.load_database)
        if self.__is_sig_database: self.actionUnload.triggered.connect(self.database.unload)
        self.action_Update.triggered.connect(self.update_database)
        self.action_DataSettings.triggered.connect(self.open_data_settings)

        self.scan_running = False
        self.start_time = None
        self.btnStartStop.clicked.connect(lambda: self.start_scan())
        self.btnBrowse.clicked.connect(self._browse_scan_path)
        if self.settings['load_on_start']: self.load_database()

    def __scan_func_wrapper(self, func, func_args: list = None):
        """
        if not self.txtPath.text():
            show_dialog('This scan requires a file path to be entered, '
                        'please enter the path in the scan input box.', self, title='File Path Required',
                        error=True, modal=True)
            return
        """
        args = []
        if func_args:
            for arg in func_args:
                if arg == SCAN_PATH_WILDCARD:
                    value, accepted = QtWidgets.QInputDialog.getText(self, 'Path',
                                                                     'Please enter a path to scan:',
                                                                     text=self.txtPath.text())
                else:
                    value, accepted = QtWidgets.QInputDialog.getDouble(self, 'Argument for Scan',
                                                                       f'Please input a value for "{arg}":',
                                                                       1, 0, 100000, 2)
                if not accepted: return
                args.append(value)

        self.start_scan(func(*args))

    @property
    def __is_sig_database(self):
        return isinstance(self.database, HashDatabase)

    def generate_settings(self):
        if os.path.exists(SETTINGS_FILENAME): return
        self.settings = DEFAULT_SETTINGS
        self.save_settings()

    def update_settings(self):
        db_type = self.settings['database_type']
        if self._old_db_type is None or self._old_db_type != db_type:
            if db_type == DB_TYPE_HASH:
                self.database = HashDatabase(load=False, on_load_fn=self.__on_load)
            elif db_type == DB_TYPE_AI:
                self.database = NNDatabase(gpu=self.settings['use_gpu'], thread_safe=False, load=False,
                                           scan_side_calc=True, on_load_fn=self.__on_load)
            elif db_type == DB_TYPE_DUMMY:
                self.database = BaseDatabase(on_load_fn=self.__on_load)
            else:
                raise ValueError(f'Invalid database type encountered: {db_type}')
            self._old_db_type = deepcopy(db_type)
        self.scanner = Scanner(self.database)
        self.database.chunksize = self.settings['data_load_chsz']
        if self.__is_sig_database:
            self.database.update_obj.workers = self.settings['data_workers']
            self.database.update_obj.chunksize = self.settings['update_chsz']
        else:
            self.database.gpu = self.settings['use_gpu']
        self.scanner.workers = self.settings['scan_workers']
        self.scanner.scan_chunksize = self.settings['scan_chsz']
        self.scanner.load_chunksize = self.settings['scan_load_chsz']
        self.scanner.scan_archives = self.settings['scan_archives']
        self.save_settings()

    def load_settings(self):
        with open(SETTINGS_FILENAME) as f:
            self.settings.update_obj(json.load(f))

    def save_settings(self):
        with open(SETTINGS_FILENAME, 'w') as f:
            json.dump(self.settings, f)

    def load_database(self):
        self.dialog = CancelDialog()
        self.dialog.lblMsg.setText('Loading database...')
        self.dialog.setWindowTitle('Loading')
        self.dialog.buttonBox.deleteLater()
        self.dialog.buttonBox = None
        self.dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.dialog.show()

        try:
            if self.__is_sig_database: self.database.clear()
            self.database.load(block=False)
        except LoadError as e:
            self.dialog.close()
            show_dialog(f'Failed to load database. Error {e}', self, title='Error', error=True)

        # self.__load_timer.start()

    def __check_load_done(self):
        if self.database.loaded:
            self.__load_timer.stop()
            self.__on_load()

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
            except (LoadError, IOError, OSError, MemoryError) as e:
                self.database.path = old_path
                show_dialog(f'Failed to load database. Error: {e}', self, title='Error', error=True)

    def __check_update_done(self):
        if self.__update.state == HashUpdate.STATE_IDLE:
            self.dialog.close()
            self.__update_timer.stop()
            show_dialog(f'Database updated. New version: {self.database.version}', self, title='Database Updated')

    def check_update(self) -> bool:
        if self.__is_sig_database:
            self._set_loading()
            value = self.database.update_obj.check().available
            self._set_loading(False)
            return value
        else:
            return False

    def update_database(self):
        if not self.__is_sig_database:
            show_dialog('The loaded database is not updatable.', self, "Can't Update", error=True)
            return
        self.__update = self.database.update_obj
        if not self.check_update():
            show_dialog(f'Database up to date. Version {self.database.version}', self, title='Up to Date')
            return

        self.dialog = CancelDialog()
        self.dialog.lblMsg.setText('Updating database...')
        self.dialog.setWindowTitle('Updating Database')
        self.dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.dialog.buttonBox.rejected.connect(self.__update.stop)
        self.dialog.show()
        self.database.clear()
        self.__update.apply_async(load_into_memory=False)
        self.__update_timer.start()

    def save_report(self):
        path, accepted = QtWidgets.QInputDialog.getText(self, 'Filename',
                                                        'Filename for the generated report (leave blank for default):')
        if not accepted: return

        try:
            path = self.scanner.generate_report(report_file=path, verbose=True)
        except IOError as e:
            show_dialog('Failed to save the scan report. Error: ' + str(e), self, 'Error', error=True)
        else:
            show_dialog(f'Saved scan report to "{path}"', self, 'Success')

    def open_settings(self):
        self.win_settings = SettingsWindow(self.settings)
        self.win_settings.closing.connect(self.__settings_from_main)
        self.win_settings.update_gui()
        self.win_settings.show()

    def __settings_from_main(self):
        self.settings = self.win_settings.settings
        self.update_settings()

    def __settings_from_data(self):
        self.settings = self.win_data_settings.settings
        self.update_settings()

    def open_data_settings(self):
        self.win_data_settings = DataSettingsWindow(self.settings)
        self.win_data_settings.gui_update.connect(self.__update_data_labels)
        self.win_data_settings.closing.connect(self.__settings_from_data)
        self.win_data_settings.btnLoad.clicked.connect(self.load_database)
        self.win_data_settings.btnLoadCustom.clicked.connect(self.load_custom_database)
        self.win_data_settings.btnUpdate.clicked.connect(self.update_database)
        self.win_data_settings.update_gui()
        self.win_data_settings.show()

    def __update_data_labels(self):
        loaded = self.database.loaded
        if self.__is_sig_database:
            signatures = self.database.signatures
            version = self.database.version
            update = self.check_update()
        else:
            signatures = 'N/A'
            version = 'N/A'
            update = 'N/A'

        self.win_data_settings.lblSignatures.setText(f'Signatures: {signatures}')
        self.win_data_settings.lblVersion.setText(f'Version: {version}')
        self.win_data_settings.lblLoaded.setText(f'Database Loaded: {loaded}')
        self.win_data_settings.lblUpdate.setText(f'Update Available: {update}')

    def _browse_scan_path(self):
        path = file_or_folder_dialog(self)
        if path:
            self.txtPath.setText(path)

    def _set_status(self, status: str):
        if self.lblStatus.text() != status:
            self.lblStatus.setText(status)
            self.lblStatus.adjustSize()

    @staticmethod
    def _set_loading(value: bool = True):
        if value:
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        else:
            QtWidgets.QApplication.restoreOverrideCursor()

    def start_scan(self, query: ScanQuery = None):
        if self.scan_running:
            self.finish_scan()
            return

        path = self.txtPath.text() if query is None else query
        if isinstance(path, str) and not os.path.exists(path):
            show_dialog('Invalid directory entered.', self, title='Error', error=True)
            return

        if not self.database.loaded:
            show_dialog('Cannot scan because the database is not loaded.',
                        self, title='Database Not Loaded', error=True)
            return

        self.scan_running = True
        self.lstScanned.clearContents()
        self.lstScanned.setRowCount(0)
        self.lstThreats.clearContents()
        self.lstThreats.setRowCount(0)
        self.progressBar.reset()
        self.btnBrowse.setEnabled(False)
        self.btnStartStop.setText('Stop')
        self.btnStartStop.setEnabled(True)
        self.start_time = time.time()
        self.scanner.scan_async(path, subdirs=self.settings['scan_subdirs'],
                                load_while_scanning=self.settings['load_while_scanning'])
        self.__scan_timer.start()

    def __update_timesince(self):
        self.lblTimeElapsed.setText(f'Time elapsed: {round(utils.timesince(self.start_time), 2)} s')
        self.lblTimeElapsed.adjustSize()

    def __scan_update(self):
        if self.scanner.state == Scanner.STATE_LOAD_PATHS:
            self._set_status('Preparing...')
        else:
            self._set_status('Scanning')

        all_files = len(self.scanner.all_files)

        scanned = len(list(filter(lambda x: not x.details.get('in_archive'), self.scanner.results)))
        total_files = all_files - len(self.scanner.not_scanned)
        try:
            self.progressBar.setValue(scanned / total_files * 100)
        except ZeroDivisionError:
            pass

        self.lblScanned.setText(f'Scanned: {scanned}/{all_files} files ({len(self.scanner.results)} items)')
        self.lblScanned.adjustSize()
        self.lblThreats.setText(f'Threats: {len(self.scanner.infected)}')
        self.__update_timesince()
        remaining = round(utils.estimate_time(total_files, scanned, self.start_time), 1)
        if remaining < 0: remaining = 0
        self.lblTimeRemaining.setText(
            f'Remaining: {remaining} s'
        )

        font = QtGui.QFont()
        font.setFamily("Trebuchet MS")
        font.setPointSize(10)
        n_displayed = self.lstScanned.rowCount()

        for result in self.scanner.results[n_displayed:]:
            item_path = QtWidgets.QTableWidgetItem(result.path)
            item_path.setFont(font)
            item_result = QtWidgets.QTableWidgetItem('infected' if result.malicious else 'clean')
            item_result.setFont(font)
            self.lstScanned.insertRow(n_displayed)
            self.lstScanned.setItem(n_displayed, 0, item_path)
            self.lstScanned.setItem(n_displayed, 1, item_result)
            if result.malicious:
                item_path = QtWidgets.QTableWidgetItem(result.path)
                item_path.setFont(font)
                item_details = QtWidgets.QTableWidgetItem(','.join([f'{str(k)}: {str(v)}' for k, v in
                                                                    result.details.items()]))
                item_details.setFont(font)
                row = self.lstThreats.rowCount()
                self.lstThreats.insertRow(row)
                self.lstThreats.setItem(row, 0, item_path)
                self.lstThreats.setItem(row, 1, item_details)

        if n_displayed != len(self.scanner.results):
            self.lstScanned.resizeRowsToContents()
            self.lstScanned.resizeColumnToContents(0)
            self.lstScanned.scrollToBottom()
            self.lstThreats.resizeColumnToContents(0)
            self.lstThreats.resizeColumnToContents(1)
            self.lstThreats.resizeRowsToContents()
            self.lstThreats.scrollToBottom()

        if self.scanner.state == Scanner.STATE_IDLE: self.finish_scan()

    def finish_scan(self):
        self.__scan_timer.stop()
        self.__update_timesince()
        self.progressBar.setValue(100)
        self.scanner.stop_scan(block=False)
        self.scan_running = False
        self.btnBrowse.setEnabled(True)
        self.btnStartStop.setText('Start')
        self._set_status('Ready')

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        self.save_settings()
        a0.accept()


if __name__ == "__main__":
    import sys

    QtCore.pyqtRemoveInputHook()

    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
