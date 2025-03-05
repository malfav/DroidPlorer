import sys
import subprocess
import re
import time
from PyQt5 import QtWidgets, QtCore, QtGui

# ----------------------------
# Helper: Check ADB Connection
# ----------------------------
def check_adb_connection():
    """
    Checks if an ADB-connected device is available.
    """
    try:
        output = subprocess.check_output(["adb", "devices"]).decode()
        lines = output.strip().splitlines()
        if len(lines) > 1:
            devices = [line for line in lines[1:] if line.strip() and "device" in line]
            return len(devices) > 0
        else:
            return False
    except Exception:
        return False

# ----------------------------
# Process Monitoring Thread
# ----------------------------
class ProcessMonitorThread(QtCore.QThread):
    process_updated = QtCore.pyqtSignal(list)  # Emits list of process dicts
    process_event = QtCore.pyqtSignal(str, dict)  # Emits event type and process info

    def __init__(self, parent=None):
        super(ProcessMonitorThread, self).__init__(parent)
        self._running = True
        self.previous_processes = {}  # key: pid, value: process dict

    def run(self):
        while self._running:
            current_processes = self.get_processes()
            # Detect new processes
            for pid, proc in current_processes.items():
                if pid not in self.previous_processes:
                    proc['event'] = 'created'
                    self.process_event.emit("created", proc)
                else:
                    # Check for state changes (e.g., suspended if STAT contains "T")
                    old_proc = self.previous_processes[pid]
                    if 'stat' in proc and proc['stat'] != old_proc.get('stat', ''):
                        if "T" in proc['stat']:
                            proc['event'] = 'suspended'
                            self.process_event.emit("suspended", proc)
                        else:
                            proc['event'] = 'running'
            # Detect killed processes
            for pid, proc in self.previous_processes.items():
                if pid not in current_processes:
                    proc['event'] = 'killed'
                    self.process_event.emit("killed", proc)
            self.previous_processes = current_processes
            self.process_updated.emit(list(current_processes.values()))
            time.sleep(2)

    def get_processes(self):
        processes = {}
        try:
            # Try using an extended ps format (with STAT column)
            output = subprocess.check_output(["adb", "shell", "ps", "-o", "USER,PID,PPID,STAT,NAME"]).decode()
            lines = output.strip().splitlines()
            if len(lines) > 1:
                headers = re.split(r'\s+', lines[0].strip())
                try:
                    stat_index = headers.index("STAT")
                except ValueError:
                    stat_index = None
                for line in lines[1:]:
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 5:
                        user = parts[0]
                        pid = parts[1]
                        ppid = parts[2]
                        stat = parts[3] if stat_index is not None else ""
                        name = parts[4]
                        processes[pid] = {"user": user, "pid": pid, "ppid": ppid, "stat": stat, "name": name, "event": "running"}
            else:
                # Fallback for older devices
                output = subprocess.check_output(["adb", "shell", "ps"]).decode()
                lines = output.strip().splitlines()
                for line in lines[1:]:
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 9:
                        user = parts[0]
                        pid = parts[1]
                        ppid = parts[2]
                        name = parts[-1]
                        processes[pid] = {"user": user, "pid": pid, "ppid": ppid, "name": name, "event": "running"}
        except Exception as e:
            print(f"Error retrieving processes: {e}")
        return processes

    def stop(self):
        self._running = False
        self.wait()

# ----------------------------
# Package Monitoring Thread
# ----------------------------
class PackageMonitorThread(QtCore.QThread):
    packages_updated = QtCore.pyqtSignal(list)
    package_event = QtCore.pyqtSignal(str, str)  # event type and package name

    def __init__(self, parent=None):
        super(PackageMonitorThread, self).__init__(parent)
        self._running = True
        self.previous_packages = set()

    def run(self):
        while self._running:
            current_packages = self.get_packages()
            new_packages = current_packages - self.previous_packages
            for pkg in new_packages:
                self.package_event.emit("installed", pkg)
            self.previous_packages = current_packages
            self.packages_updated.emit(sorted(list(current_packages)))
            time.sleep(10)

    def get_packages(self):
        packages = set()
        try:
            output = subprocess.check_output(["adb", "shell", "pm", "list", "packages"]).decode()
            lines = output.strip().splitlines()
            for line in lines:
                if line.startswith("package:"):
                    pkg = line.split("package:")[1].strip()
                    packages.add(pkg)
        except Exception as e:
            print(f"Error retrieving packages: {e}")
        return packages

    def stop(self):
        self._running = False
        self.wait()

# ----------------------------
# Network Monitoring Thread
# ----------------------------
class NetworkMonitorThread(QtCore.QThread):
    network_updated = QtCore.pyqtSignal(list)

    def __init__(self, parent=None):
        super(NetworkMonitorThread, self).__init__(parent)
        self._running = True

    def run(self):
        while self._running:
            connections = self.get_network_connections()
            self.network_updated.emit(connections)
            time.sleep(5)

    def get_network_connections(self):
        conns = []
        try:
            output = subprocess.check_output(["adb", "shell", "netstat", "-an"]).decode()
            lines = output.strip().splitlines()
            for line in lines[1:]:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4:
                    proto = parts[0]
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3] if len(parts) > 3 else ""
                    conns.append({"proto": proto, "local": local, "remote": remote, "state": state})
        except Exception as e:
            print(f"Error retrieving network connections: {e}")
        return conns

    def stop(self):
        self._running = False
        self.wait()

# ----------------------------
# File Monitoring Thread using adb logcat
# ----------------------------
class FileMonitorThread(QtCore.QThread):
    file_event = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super(FileMonitorThread, self).__init__(parent)
        self._running = True
        self.proc = None

    def run(self):
        try:
            # Start adb logcat with time stamps
            self.proc = subprocess.Popen(
                ["adb", "logcat", "-v", "time"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            while self._running:
                line = self.proc.stdout.readline()
                if not line:
                    break
                # Improved filtering: only log lines that match common file activity keywords
                if any(keyword in line.lower() for keyword in ["file", "open(", "read(", "write("]):
                    self.file_event.emit(line.strip())
        except Exception as e:
            print(f"Error in FileMonitorThread: {e}")

    def stop(self):
        self._running = False
        if self.proc:
            self.proc.terminate()
        self.wait()

# ----------------------------
# Package Analysis Thread
# ----------------------------
class PackageAnalysisThread(QtCore.QThread):
    analysis_ready = QtCore.pyqtSignal(dict)

    def __init__(self, package, parent=None):
        super(PackageAnalysisThread, self).__init__(parent)
        self.package = package

    def run(self):
        filters = {
            "Libraries": ["lib", "library", "native"],
            "Permissions": ["permission"],
            "Activities": ["Activity", "activity"],
            "API Calls": ["api", "call"],
            "Receivers": ["Receiver", "receiver"],
            "Services": ["Service", "service"],
            "Providers": ["Provider", "provider"],
            "Files": ["file", "File"]
        }
        analysis_result = {}
        try:
            output = subprocess.check_output(
                ["adb", "shell", "dumpsys", "package", self.package],
                stderr=subprocess.STDOUT
            ).decode(errors="ignore")
            lines = output.splitlines()
            for key, keywords in filters.items():
                filtered = [line for line in lines if any(kw in line for kw in keywords)]
                analysis_result[key] = "\n".join(filtered) if filtered else f"No {key} information found."
        except Exception as e:
            for key in filters.keys():
                analysis_result[key] = f"Error retrieving {key} info: {e}"
        self.analysis_ready.emit(analysis_result)

# ----------------------------
# Process Detail Dialog
# ----------------------------
class ProcessDetailDialog(QtWidgets.QDialog):
    def __init__(self, process_info, parent=None):
        super(ProcessDetailDialog, self).__init__(parent)
        self.setWindowTitle(f"Process Detail - {process_info.get('name','')}")
        layout = QtWidgets.QGridLayout()
        row = 0
        for key, value in process_info.items():
            layout.addWidget(QtWidgets.QLabel(f"{key}: "), row, 0)
            layout.addWidget(QtWidgets.QLabel(f"{value}"), row, 1)
            row += 1
        detail_text = QtWidgets.QTextEdit()
        detail_text.setReadOnly(True)
        detail_text.setText("Additional details (e.g., network connections, child processes) can be retrieved via further adb commands...")
        layout.addWidget(detail_text, row, 0, 1, 2)
        self.setLayout(layout)

# ----------------------------
# Package Detail Dialog
# ----------------------------
class PackageDetailDialog(QtWidgets.QDialog):
    def __init__(self, package_name, parent=None):
        super(PackageDetailDialog, self).__init__(parent)
        self.setWindowTitle(f"Package Detail - {package_name}")
        layout = QtWidgets.QVBoxLayout()
        detail_text = QtWidgets.QTextEdit()
        detail_text.setReadOnly(True)
        try:
            output = subprocess.check_output(["adb", "shell", "dumpsys", "package", package_name]).decode(errors="ignore")
            detail_text.setText(output)
        except Exception as e:
            detail_text.setText(f"Error retrieving package details: {e}")
        layout.addWidget(detail_text)
        self.setLayout(layout)

# ----------------------------
# Main Window with Advanced Dashboard
# ----------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Android System Monitor")
        self.setGeometry(100, 100, 1100, 750)
        self._init_ui()
        self._init_threads()
        self.current_analysis_package = None

    def _init_ui(self):
        # Apply a basic style sheet for a modern look
        self.setStyleSheet("""
            QMainWindow { background-color: #f0f0f0; }
            QTableWidget { background-color: white; gridline-color: #ccc; }
            QTextEdit { background-color: white; }
            QLabel { font-weight: bold; }
        """)
        self.tab_widget = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Processes Tab
        self.process_tab = QtWidgets.QWidget()
        process_layout = QtWidgets.QVBoxLayout()
        self.process_table = QtWidgets.QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["User", "PID", "PPID", "Name", "Status"])
        self.process_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.process_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        process_layout.addWidget(self.process_table)
        self.process_event_log = QtWidgets.QTextEdit()
        self.process_event_log.setReadOnly(True)
        self.process_event_log.setFixedHeight(150)
        process_layout.addWidget(self.process_event_log)
        self.process_tab.setLayout(process_layout)
        self.tab_widget.addTab(self.process_tab, "Processes")

        # Packages Tab
        self.package_tab = QtWidgets.QWidget()
        package_layout = QtWidgets.QVBoxLayout()
        self.package_table = QtWidgets.QTableWidget()
        self.package_table.setColumnCount(1)
        self.package_table.setHorizontalHeaderLabels(["Package Name"])
        self.package_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.package_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        package_layout.addWidget(self.package_table)
        # Package Event Log
        self.package_event_log = QtWidgets.QTextEdit()
        self.package_event_log.setReadOnly(True)
        self.package_event_log.setFixedHeight(100)
        package_layout.addWidget(self.package_event_log)
        self.package_tab.setLayout(package_layout)
        self.tab_widget.addTab(self.package_tab, "Packages")

        # File Activity Tab
        self.file_tab = QtWidgets.QWidget()
        file_layout = QtWidgets.QVBoxLayout()
        self.file_event_log = QtWidgets.QTextEdit()
        self.file_event_log.setReadOnly(True)
        file_layout.addWidget(self.file_event_log)
        self.file_tab.setLayout(file_layout)
        self.tab_widget.addTab(self.file_tab, "File Activity")

        # Network Activity Tab
        self.network_tab = QtWidgets.QWidget()
        network_layout = QtWidgets.QVBoxLayout()
        self.network_table = QtWidgets.QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(["Proto", "Local Address", "Remote Address", "State"])
        self.network_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.network_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        network_layout.addWidget(self.network_table)
        self.network_tab.setLayout(network_layout)
        self.tab_widget.addTab(self.network_tab, "Network Activity")

        # App Analysis Tab (with sub-tabs)
        self.analysis_tab = QtWidgets.QWidget()
        analysis_layout = QtWidgets.QVBoxLayout()
        self.analysis_label = QtWidgets.QLabel("No package selected for analysis.")
        analysis_layout.addWidget(self.analysis_label)
        self.analysis_tabs = QtWidgets.QTabWidget()
        self.analysis_subtabs = {}
        for name in ["Libraries", "Permissions", "Activities", "API Calls", "Receivers", "Services", "Providers", "Files"]:
            text_edit = QtWidgets.QTextEdit()
            text_edit.setReadOnly(True)
            self.analysis_subtabs[name] = text_edit
            self.analysis_tabs.addTab(text_edit, name)
        analysis_layout.addWidget(self.analysis_tabs)
        self.analysis_tab.setLayout(analysis_layout)
        self.tab_widget.addTab(self.analysis_tab, "App Analysis")

        # Connect double-click signals for details and analysis
        self.process_table.doubleClicked.connect(self.show_process_details)
        self.package_table.doubleClicked.connect(self.package_double_clicked)

    def _init_threads(self):
        # Start monitoring threads
        self.process_thread = ProcessMonitorThread()
        self.process_thread.process_updated.connect(self.update_process_table)
        self.process_thread.process_event.connect(self.handle_process_event)
        self.process_thread.start()

        self.package_thread = PackageMonitorThread()
        self.package_thread.packages_updated.connect(self.update_package_table)
        self.package_thread.package_event.connect(self.handle_package_event)
        self.package_thread.start()

        self.network_thread = NetworkMonitorThread()
        self.network_thread.network_updated.connect(self.update_network_table)
        self.network_thread.start()

        self.file_thread = FileMonitorThread()
        self.file_thread.file_event.connect(self.update_file_log)
        self.file_thread.start()

    # ----------------------------
    # UI Update Methods
    # ----------------------------
    def update_process_table(self, processes):
        self.process_table.setRowCount(0)
        for proc in processes:
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            user_item = QtWidgets.QTableWidgetItem(proc.get("user", ""))
            pid_item = QtWidgets.QTableWidgetItem(proc.get("pid", ""))
            ppid_item = QtWidgets.QTableWidgetItem(proc.get("ppid", ""))
            name_item = QtWidgets.QTableWidgetItem(proc.get("name", ""))
            status = proc.get("event", "running")
            status_item = QtWidgets.QTableWidgetItem(status)
            # Colorize based on event status
            if status == "created":
                for item in (user_item, pid_item, ppid_item, name_item, status_item):
                    item.setBackground(QtGui.QColor("lightgreen"))
            elif status == "killed":
                for item in (user_item, pid_item, ppid_item, name_item, status_item):
                    item.setBackground(QtGui.QColor("lightcoral"))
            elif status == "suspended":
                for item in (user_item, pid_item, ppid_item, name_item, status_item):
                    item.setBackground(QtGui.QColor("lightyellow"))
            self.process_table.setItem(row, 0, user_item)
            self.process_table.setItem(row, 1, pid_item)
            self.process_table.setItem(row, 2, ppid_item)
            self.process_table.setItem(row, 3, name_item)
            self.process_table.setItem(row, 4, status_item)

    def handle_process_event(self, event_type, proc):
        timestamp = time.strftime("%H:%M:%S")
        if event_type == "created":
            self.process_event_log.append(f"<font color='green'>[{timestamp}] Process created: {proc.get('name','')} (PID: {proc.get('pid','')})</font>")
        elif event_type == "killed":
            self.process_event_log.append(f"<font color='red'>[{timestamp}] Process killed: {proc.get('name','')} (PID: {proc.get('pid','')})</font>")
        elif event_type == "suspended":
            self.process_event_log.append(f"<font color='orange'>[{timestamp}] Process suspended: {proc.get('name','')} (PID: {proc.get('pid','')})</font>")

    def update_package_table(self, packages):
        self.package_table.setRowCount(0)
        for pkg in packages:
            row = self.package_table.rowCount()
            self.package_table.insertRow(row)
            item = QtWidgets.QTableWidgetItem(pkg)
            self.package_table.setItem(row, 0, item)

    def handle_package_event(self, event_type, pkg):
        timestamp = time.strftime("%H:%M:%S")
        if event_type == "installed":
            self.package_event_log.append(f"<font color='blue'>[{timestamp}] New package installed: {pkg}</font>")

    def update_network_table(self, connections):
        self.network_table.setRowCount(0)
        for conn in connections:
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            proto_item = QtWidgets.QTableWidgetItem(conn.get("proto", ""))
            local_item = QtWidgets.QTableWidgetItem(conn.get("local", ""))
            remote_item = QtWidgets.QTableWidgetItem(conn.get("remote", ""))
            state_item = QtWidgets.QTableWidgetItem(conn.get("state", ""))
            self.network_table.setItem(row, 0, proto_item)
            self.network_table.setItem(row, 1, local_item)
            self.network_table.setItem(row, 2, remote_item)
            self.network_table.setItem(row, 3, state_item)

    def update_file_log(self, line):
        self.file_event_log.append(line)

    # ----------------------------
    # Detail and Analysis Methods
    # ----------------------------
    def show_process_details(self, index):
        row = index.row()
        pid_item = self.process_table.item(row, 1)
        if pid_item:
            pid = pid_item.text()
            user = self.process_table.item(row, 0).text()
            ppid = self.process_table.item(row, 2).text()
            name = self.process_table.item(row, 3).text()
            status = self.process_table.item(row, 4).text()
            process_info = {"user": user, "pid": pid, "ppid": ppid, "name": name, "status": status}
            dialog = ProcessDetailDialog(process_info, self)
            dialog.exec_()

    def package_double_clicked(self, index):
        row = index.row()
        pkg_item = self.package_table.item(row, 0)
        if pkg_item:
            package = pkg_item.text()
            # Show package details dialog
            dialog = PackageDetailDialog(package, self)
            dialog.exec_()
            # Also update the App Analysis tab
            self.analyze_package(package)

    def analyze_package(self, package):
        self.current_analysis_package = package
        self.analysis_label.setText(f"Analysis for package: {package}")
        self.analysis_label.repaint()
        # Start background analysis
        self.analysis_thread = PackageAnalysisThread(package)
        self.analysis_thread.analysis_ready.connect(self.update_analysis_tab)
        self.analysis_thread.start()

    def update_analysis_tab(self, analysis_dict):
        for key, text_edit in self.analysis_subtabs.items():
            text_edit.clear()
            text_edit.setText(analysis_dict.get(key, f"No {key} information found."))

    # ----------------------------
    # Cleanup on Close
    # ----------------------------
    def closeEvent(self, event):
        self.process_thread.stop()
        self.package_thread.stop()
        self.network_thread.stop()
        self.file_thread.stop()
        event.accept()

# ----------------------------
# Main Entry Point
# ----------------------------
if __name__ == "__main__":
    if not check_adb_connection():
        QtWidgets.QMessageBox.critical(None, "ADB Error", "No ADB-connected device found. Please connect a device and try again.")
        sys.exit(1)
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
