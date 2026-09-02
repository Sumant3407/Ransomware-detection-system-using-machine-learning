"""Functional PySide6 dashboard with light and dark themes."""

import json
import csv
import sqlite3
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.config.configuration import getDataDirectory, getProjectRoot, loadConfiguration, resolveMonitoringPath
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.runtime.controller import DetectionController
from app.runtime.worker import MonitoringWorker
from app.monitoring.fileEvents import getSnapshot
from trainingModel.unlearning.unlearnModel import unlearnLabel


class StatusCard(QFrame):
    def __init__(self, title: str, value: str, accent: str):
        super().__init__()
        self.setObjectName("statusCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(7)
        titleLabel = QLabel(title.upper())
        titleLabel.setObjectName("cardTitle")
        self.valueLabel = QLabel(value)
        self.valueLabel.setObjectName("cardValue")
        self.valueLabel.setStyleSheet(f"color: {accent}; background: transparent; border: none;")
        layout.addWidget(titleLabel)
        layout.addWidget(self.valueLabel)

    def setValue(self, value: str, accent: str | None = None) -> None:
        self.valueLabel.setText(value)
        if accent:
            self.valueLabel.setStyleSheet(f"color: {accent}; background: transparent; border: none;")


class MainWindow(QMainWindow):
    decisionChanged = Signal(str, float)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ransomware Detector")
        self.setMinimumSize(900, 620)
        self.workerThread: QThread | None = None
        self.worker: MonitoringWorker | None = None
        self.eventCount = 0
        self.configuration = loadConfiguration()
        self.isDarkTheme = self.configuration.get("ui", {}).get("theme", "dark") == "dark"
        self.databasePath = getDataDirectory() / "database" / "detector.sqlite3"
        self.monitoringPath = resolveMonitoringPath(self.configuration["monitoring"]["paths"][0])
        self.modelPath = self.getModelPath()
        self.buildInterface()
        self.applyTheme()
        self.refreshStatus()
        self.loadHistory()

    def getModelPath(self) -> Path:
        modelPath = Path(self.configuration["model"].get("path", ""))
        return modelPath if modelPath.is_absolute() else getProjectRoot() / modelPath

    def buildInterface(self) -> None:
        rootWidget = QWidget()
        rootLayout = QVBoxLayout(rootWidget)
        rootLayout.setContentsMargins(28, 24, 28, 24)
        rootLayout.setSpacing(18)

        headerLayout = QHBoxLayout()
        titleBlock = QVBoxLayout()
        titleLabel = QLabel("Ransomware Detector")
        titleLabel.setObjectName("pageTitle")
        subtitleLabel = QLabel("Local behavioral protection")
        subtitleLabel.setObjectName("subtitle")
        titleBlock.addWidget(titleLabel)
        titleBlock.addWidget(subtitleLabel)
        headerLayout.addLayout(titleBlock)
        headerLayout.addStretch()
        self.themeButton = QPushButton("Light theme")
        self.themeButton.setObjectName("secondaryButton")
        self.themeButton.clicked.connect(self.toggleTheme)
        headerLayout.addWidget(self.themeButton)
        self.protectionButton = QPushButton("Start protection")
        self.protectionButton.setObjectName("primaryButton")
        self.protectionButton.clicked.connect(self.toggleProtection)
        headerLayout.addWidget(self.protectionButton)
        rootLayout.addLayout(headerLayout)

        self.statusBanner = QLabel("Protection ready")
        self.statusBanner.setObjectName("statusBanner")
        rootLayout.addWidget(self.statusBanner)

        self.protectionCard = StatusCard("Protection", "Limited", "#ffca70")
        self.threatCard = StatusCard("Threat level", "Low", "#68e0a0")
        self.filesCard = StatusCard("Files monitored", "0", "#8bb8ff")
        self.detectionsCard = StatusCard("Detections", "0", "#ffca70")
        cardsLayout = QGridLayout()
        cardsLayout.setSpacing(12)
        for index, card in enumerate((self.protectionCard, self.threatCard, self.filesCard, self.detectionsCard)):
            cardsLayout.addWidget(card, 0, index)
        rootLayout.addLayout(cardsLayout)

        actionLayout = QHBoxLayout()
        self.scanButton = QPushButton("Scan now")
        self.scanButton.setObjectName("secondaryButton")
        self.scanButton.clicked.connect(self.scanNow)
        refreshButton = QPushButton("Refresh status")
        refreshButton.setObjectName("secondaryButton")
        refreshButton.clicked.connect(self.refreshAll)
        actionLayout.addWidget(self.scanButton)
        actionLayout.addWidget(refreshButton)
        actionLayout.addStretch()
        rootLayout.addLayout(actionLayout)

        self.tabs = QTabWidget()
        self.historyList = QListWidget()
        self.historyList.setAlternatingRowColors(True)
        self.historyList.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        historyActions = QHBoxLayout()
        clearHistoryButton = QPushButton("Clear history")
        clearHistoryButton.setObjectName("secondaryButton")
        clearHistoryButton.clicked.connect(self.clearHistory)
        exportHistoryButton = QPushButton("Export history")
        exportHistoryButton.setObjectName("secondaryButton")
        exportHistoryButton.clicked.connect(self.exportHistory)
        historyActions.addWidget(clearHistoryButton)
        historyActions.addWidget(exportHistoryButton)
        historyActions.addStretch()
        historyPage = QWidget()
        historyLayout = QVBoxLayout(historyPage)
        historyLayout.addLayout(historyActions)
        historyLayout.addWidget(self.historyList)
        self.tabs.addTab(historyPage, "Detection history")
        self.tabs.addTab(self.createModelPage(), "Model")
        self.tabs.addTab(self.createUnlearningPage(), "Unlearning")
        self.tabs.addTab(self.createSettingsPage(), "Settings")
        rootLayout.addWidget(self.tabs, 1)

        footerLabel = QLabel("Offline mode  |  Response policy: alert only")
        footerLabel.setObjectName("footer")
        rootLayout.addWidget(footerLabel)
        self.setCentralWidget(rootWidget)

    def createModelPage(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        heading = QLabel("Model status")
        heading.setObjectName("sectionTitle")
        self.modelStatusLabel = QLabel()
        self.modelStatusLabel.setObjectName("infoRow")
        validateButton = QPushButton("Validate model")
        validateButton.setObjectName("secondaryButton")
        validateButton.clicked.connect(self.validateModel)
        layout.addWidget(heading)
        layout.addWidget(self.modelStatusLabel)
        layout.addWidget(validateButton, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()
        self.validateModel()
        return page

    def createUnlearningPage(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        heading = QLabel("Exact-retraining unlearning")
        heading.setObjectName("sectionTitle")
        self.forgetLabelInput = QLineEdit()
        self.forgetLabelInput.setPlaceholderText("Label to remove, for example Ransomware")
        self.unlearningStatusLabel = QLabel("No operation running")
        self.unlearningStatusLabel.setObjectName("infoRow")
        unlearnButton = QPushButton("Create candidate model")
        unlearnButton.setObjectName("secondaryButton")
        unlearnButton.clicked.connect(self.runUnlearning)
        layout.addWidget(heading)
        layout.addWidget(QLabel("Label"))
        layout.addWidget(self.forgetLabelInput)
        layout.addWidget(unlearnButton, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.unlearningStatusLabel)
        layout.addStretch()
        return page

    def createSettingsPage(self) -> QWidget:
        page = QWidget()
        layout = QFormLayout(page)
        heading = QLabel("Settings")
        heading.setObjectName("sectionTitle")
        self.sensitivityInput = QComboBox()
        self.sensitivityInput.addItems(["conservative", "balanced", "aggressive"])
        self.sensitivityInput.setCurrentText(self.configuration["monitoring"]["sensitivity"])
        self.notificationsInput = QCheckBox("Enable notifications")
        self.notificationsInput.setChecked(self.configuration["notifications"]["enabled"])
        saveButton = QPushButton("Save settings")
        saveButton.setObjectName("secondaryButton")
        saveButton.clicked.connect(self.saveSettings)
        self.settingsStatusLabel = QLabel("Settings loaded")
        layout.addRow(heading)
        directoryRow = QWidget()
        directoryLayout = QHBoxLayout(directoryRow)
        directoryLayout.setContentsMargins(0, 0, 0, 0)
        self.directoryLabel = QLabel(str(self.monitoringPath))
        browseButton = QPushButton("Browse")
        browseButton.setObjectName("secondaryButton")
        browseButton.clicked.connect(self.browseMonitoringDirectory)
        directoryLayout.addWidget(self.directoryLabel, 1)
        directoryLayout.addWidget(browseButton)
        layout.addRow("Monitoring directory", directoryRow)
        layout.addRow("Sensitivity", self.sensitivityInput)
        layout.addRow(self.notificationsInput)
        layout.addRow(saveButton)
        layout.addRow(self.settingsStatusLabel)
        return page

    def applyTheme(self) -> None:
        if self.isDarkTheme:
            self.setStyleSheet(self.getDarkStyle())
            self.themeButton.setText("Light theme")
        else:
            self.setStyleSheet(self.getLightStyle())
            self.themeButton.setText("Dark theme")

    def getDarkStyle(self) -> str:
        return self.getThemeStyle("#101722", "#e7eef8", "#172230", "#26384b", "#68e0a0", "#223247")

    def getLightStyle(self) -> str:
        return self.getThemeStyle("#f4f7fb", "#1c2733", "#ffffff", "#d4deea", "#16803c", "#e5edf6")

    def getThemeStyle(self, background: str, foreground: str, panel: str, border: str, accent: str, button: str) -> str:
        return f"""
            QWidget {{ background: {background}; color: {foreground}; font-family: Segoe UI; }}
            QLabel {{ background: transparent; border: none; }}
            QMainWindow {{ background: {background}; }}
            #pageTitle {{ font-size: 28px; font-weight: 700; }}
            #subtitle, #footer, #cardTitle {{ color: #8494a8; }}
            #subtitle {{ font-size: 13px; }}
            #statusBanner {{ background: #16352b; border: 1px solid #285d49; border-radius: 8px; padding: 13px; color: #93f0bd; font-weight: 600; }}
            #statusCard {{ background: {panel}; border: 1px solid {border}; border-radius: 10px; padding: 8px; }}
            #cardTitle {{ background: transparent; border: none; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
            #cardValue {{ background: transparent; border: none; font-size: 24px; font-weight: 700; padding: 0; }}
            QPushButton {{ border-radius: 7px; padding: 10px 16px; font-weight: 600; }}
            #primaryButton {{ background: {accent}; color: #102017; }}
            #secondaryButton {{ background: {button}; border: 1px solid {border}; color: {foreground}; }}
            QTabWidget::pane {{ border: 1px solid {border}; border-radius: 8px; background: {panel}; }}
            QTabBar::tab {{ background: {panel}; color: #8494a8; padding: 11px 18px; border: 0; }}
            QTabBar::tab:selected {{ color: {accent}; border-bottom: 2px solid {accent}; }}
            QListWidget {{ border: 0; background: {panel}; padding: 12px; }}
            QListWidget::item {{ padding: 10px; border-bottom: 1px solid {border}; background: {panel}; }}
            QListWidget::item:alternate {{ background: {button}; }}
            QListWidget::item:selected {{ background: {border}; color: {foreground}; }}
            QLineEdit, QComboBox {{ background: {panel}; border: 1px solid {border}; border-radius: 6px; padding: 9px; }}
            #sectionTitle {{ font-size: 21px; font-weight: 700; padding-bottom: 10px; }}
            #infoRow {{ background: {button}; border-radius: 6px; padding: 12px; }}
        """

    @Slot()
    def toggleTheme(self) -> None:
        self.isDarkTheme = not self.isDarkTheme
        self.applyTheme()
        self.saveUiSettings()

    def getController(self) -> DetectionController:
        return DetectionController(self.monitoringPath, self.databasePath, self.modelPath)

    @Slot()
    def scanNow(self) -> None:
        controller = self.getController()
        try:
            decision = controller.collectOnce()
            self.handleDecision(decision.level.value, decision.score)
            self.statusBanner.setText("Scan completed")
        except Exception as error:
            self.statusBanner.setText(f"Scan unavailable: {error}")
        finally:
            controller.close()

    @Slot()
    def toggleProtection(self) -> None:
        if self.workerThread is None:
            self.workerThread = QThread(self)
            self.worker = MonitoringWorker(self.monitoringPath, self.databasePath, self.modelPath)
            self.worker.moveToThread(self.workerThread)
            self.workerThread.started.connect(self.worker.run)
            self.worker.decisionReady.connect(self.handleDecision)
            self.worker.failed.connect(self.handleWorkerError)
            self.worker.finished.connect(self.workerThread.quit)
            self.worker.finished.connect(self.clearWorker)
            self.workerThread.finished.connect(self.workerThread.deleteLater)
            self.workerThread.start()
            self.protectionButton.setText("Stop protection")
            if self.modelAvailable:
                self.protectionCard.setValue("Protected", "#68e0a0")
                self.statusBanner.setText("Protection is monitoring the configured directory")
            else:
                self.protectionCard.setValue("Limited", "#ffca70")
                self.statusBanner.setText("Monitoring active. Add a validated model for ML classification.")
        else:
            self.worker.stop()
            self.protectionButton.setEnabled(False)
            self.statusBanner.setText("Stopping protection...")

    @Slot(str, float)
    def handleDecision(self, level: str, score: float) -> None:
        self.refreshStatus()
        threatColor = {"low": "#68e0a0", "medium": "#ffca70", "high": "#ff936e", "critical": "#ff6f8c"}.get(level, "#8bb8ff")
        self.threatCard.setValue(level.capitalize(), threatColor)
        if level != "low":
            self.historyList.insertItem(0, f"{datetime.now().strftime('%H:%M:%S')}  {level.upper()}  risk score {score:.3f}")

    @Slot(str)
    def handleWorkerError(self, message: str) -> None:
        self.statusBanner.setText(f"Monitoring unavailable: {message}")
        self.protectionCard.setValue("Limited", "#ffca70")

    @Slot()
    def clearWorker(self) -> None:
        self.worker = None
        self.workerThread = None
        self.protectionButton.setEnabled(True)
        self.protectionButton.setText("Start protection")
        self.protectionCard.setValue("Protected" if self.modelAvailable else "Limited", "#68e0a0" if self.modelAvailable else "#ffca70")
        self.statusBanner.setText("Protection stopped")

    @Slot()
    def refreshAll(self) -> None:
        self.refreshStatus()
        self.loadHistory()
        self.statusBanner.setText("Status refreshed")

    @Slot()
    def clearHistory(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            connection.execute("DELETE FROM alerts")
            connection.execute("DELETE FROM detections")
            connection.commit()
        finally:
            connection.close()
        self.loadHistory()
        self.refreshStatus()
        self.statusBanner.setText("Detection history cleared")

    @Slot()
    def exportHistory(self) -> None:
        outputPath, _ = QFileDialog.getSaveFileName(self, "Export detection history", "detections.csv", "CSV files (*.csv)")
        if not outputPath:
            return
        connection = sqlite3.connect(self.databasePath)
        try:
            rows = connection.execute("SELECT occurredAt, classification, riskScore, actionTaken FROM detections ORDER BY detectionId").fetchall()
        finally:
            connection.close()
        with open(outputPath, "w", newline="", encoding="utf-8") as outputFile:
            writer = csv.writer(outputFile)
            writer.writerow(["timestamp", "classification", "riskScore", "actionTaken"])
            writer.writerows(rows)
        self.statusBanner.setText("Detection history exported")

    @Slot()
    def refreshStatus(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            fileCount = len(getSnapshot(self.monitoringPath))
            detectionCount = connection.execute("SELECT count(*) FROM detections WHERE classification != 'benign'").fetchone()[0]
            self.filesCard.setValue(str(fileCount))
            self.detectionsCard.setValue(str(detectionCount))
        finally:
            connection.close()

    def loadHistory(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            rows = connection.execute("SELECT occurredAt, classification, riskScore FROM detections WHERE classification != 'benign' ORDER BY detectionId DESC LIMIT 50").fetchall()
        finally:
            connection.close()
        self.historyList.clear()
        for occurredAt, classification, riskScore in reversed(rows):
            self.historyList.addItem(f"{occurredAt}  {classification}  risk score {riskScore:.3f}")

    @Slot()
    def validateModel(self) -> None:
        self.modelAvailable = False
        try:
            ModelPredictor(self.modelPath)
            self.modelAvailable = True
            self.modelStatusLabel.setText(f"Status: Ready\nLocation: {self.modelPath}")
        except ModelValidationError as error:
            self.modelStatusLabel.setText(f"Status: Unavailable\nReason: {error}\nLocation: {self.modelPath}")

    @Slot()
    def saveSettings(self) -> None:
        settingsPath = getDataDirectory() / "settings.json"
        updatedConfiguration = dict(self.configuration)
        updatedConfiguration["monitoring"] = dict(updatedConfiguration["monitoring"])
        updatedConfiguration["notifications"] = dict(updatedConfiguration["notifications"])
        updatedConfiguration["monitoring"]["sensitivity"] = self.sensitivityInput.currentText()
        updatedConfiguration["notifications"]["enabled"] = self.notificationsInput.isChecked()
        updatedConfiguration.setdefault("ui", {})["theme"] = "dark" if self.isDarkTheme else "light"
        settingsPath.write_text(json.dumps(updatedConfiguration, indent=2), encoding="utf-8")
        self.configuration = updatedConfiguration
        self.settingsStatusLabel.setText(f"Saved to {settingsPath}")

    @Slot()
    def browseMonitoringDirectory(self) -> None:
        selectedPath = QFileDialog.getExistingDirectory(
            self,
            "Choose monitoring directory",
            str(self.monitoringPath),
        )
        if not selectedPath:
            return
        try:
            selectedDirectory = resolveMonitoringPath(selectedPath)
        except ValueError as error:
            self.settingsStatusLabel.setText(f"Invalid directory: {error}")
            return
        self.monitoringPath = selectedDirectory
        self.directoryLabel.setText(str(selectedDirectory))
        self.configuration.setdefault("monitoring", {})["paths"] = [str(selectedDirectory)]
        self.settingsStatusLabel.setText("Directory selected. Save settings to apply it.")

    def saveUiSettings(self) -> None:
        settingsPath = getDataDirectory() / "settings.json"
        savedConfiguration = dict(self.configuration)
        savedConfiguration.setdefault("ui", {})["theme"] = "dark" if self.isDarkTheme else "light"
        settingsPath.write_text(json.dumps(savedConfiguration, indent=2), encoding="utf-8")

    @Slot()
    def runUnlearning(self) -> None:
        label = self.forgetLabelInput.text().strip()
        if not label:
            self.unlearningStatusLabel.setText("Enter a label before starting")
            return
        datasetPath = getDataDirectory() / "ransomwareBehaviorDataset.csv"
        if not datasetPath.is_file():
            self.unlearningStatusLabel.setText("Collector dataset was not found")
            return
        try:
            import pandas as pd
            candidatePath = getDataDirectory() / "models" / "unlearned.joblib"
            metadata = unlearnLabel(pd.read_csv(datasetPath), label, candidatePath)
            self.unlearningStatusLabel.setText(f"Candidate created: {metadata['sampleCount']} remaining samples")
        except (OSError, ValueError) as error:
            self.unlearningStatusLabel.setText(f"Unlearning failed: {error}")

    def closeEvent(self, event) -> None:
        if self.worker is not None:
            self.worker.stop()
            if self.workerThread is not None:
                self.workerThread.quit()
                self.workerThread.wait(3000)
        event.accept()


def runGui() -> int:
    application = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return application.exec()
