from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, QSettings, pyqtSignal as Signal
from PyQt6.QtGui import QColor, QDragEnterEvent, QDropEvent, QFont, QPainter, QPainterPath, QPalette, QPen
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFrame, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QSizePolicy, QStackedWidget,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from analyzer import AnalysisResult, analyze_file
from history_store import HistoryStore
from reporting import write_html, write_json


ACCENT = "#55d6a5"
BG = "#0b0f14"
PANEL = "#121821"
PANEL_2 = "#171f2a"
TEXT = "#e8edf3"
MUTED = "#8995a5"
BORDER = "#263140"

I18N = {
    "tr": {
        "new": "Yeni analiz", "history": "Analiz geçmişi", "rules": "YARA kuralları",
        "local": "FILE INSPECTOR  /  YEREL", "safe": "●  YEREL ANALİZ\n\nDosyalar sunucuya\ngönderilmez.",
        "heading": "Statik dosya inceleme", "subheading": "Dosya yapısı, parmak izleri, metadata ve şüpheli göstergeler.",
        "language": "Dil", "drop": "İncelemek istediğin dosyayı bırak",
        "drop_note": "Dosya çalıştırılmaz · Analiz cihazında yapılır", "choose": "Dosya seç",
        "crypto": "Kriptografik kimlik", "crypto_d": "MD5, SHA-1 ve SHA-256 parmak izleri",
        "structure": "Yapı ve metadata", "structure_d": "Gerçek dosya türü, zamanlar ve gömülü veriler",
        "risk": "Risk göstergeleri", "risk_d": "Şüpheli API, URL, entropy ve arşiv analizi",
        "back": "←  Yeni analiz", "export": "Raporu dışa aktar", "completed": "Statik analiz tamamlandı · Dosya çalıştırılmadı",
        "risk_score": "Risk skoru", "file_type": "Dosya türü", "size": "Boyut", "entropy": "Entropy",
        "findings": "Bulgular", "details": "Teknik detaylar", "indicators": "Göstergeler", "strings": "Metinler",
        "history_title": "Analiz geçmişi", "history_note": "Son 100 yerel analiz. Dosyalar saklanmaz; yalnızca rapor özeti tutulur.",
        "clear": "Geçmişi temizle", "rules_title": "YARA kural seti", "rules_note": "Her analizde yerel olarak uygulanan teknik eşleşmeler",
    },
    "en": {
        "new": "New analysis", "history": "Analysis history", "rules": "YARA rules",
        "local": "FILE INSPECTOR  /  LOCAL", "safe": "●  LOCAL ANALYSIS\n\nFiles never leave\nthis device.",
        "heading": "Static file inspection", "subheading": "File structure, fingerprints, metadata and suspicious indicators.",
        "language": "Language", "drop": "Drop a file to inspect",
        "drop_note": "The file is never executed · Analysis stays on device", "choose": "Choose file",
        "crypto": "Cryptographic identity", "crypto_d": "MD5, SHA-1 and SHA-256 fingerprints",
        "structure": "Structure and metadata", "structure_d": "True file type, timestamps and embedded data",
        "risk": "Risk indicators", "risk_d": "Suspicious APIs, URLs, entropy and archive analysis",
        "back": "←  New analysis", "export": "Export report", "completed": "Static analysis complete · File was not executed",
        "risk_score": "Risk score", "file_type": "File type", "size": "Size", "entropy": "Entropy",
        "findings": "Findings", "details": "Technical details", "indicators": "Indicators", "strings": "Strings",
        "history_title": "Analysis history", "history_note": "Last 100 local scans. Files are not retained; only report summaries are stored.",
        "clear": "Clear history", "rules_title": "YARA ruleset", "rules_note": "Technical signatures applied locally during every analysis",
    },
}


class GraffitiLogo(QWidget):
    """Resolution-independent hand-tag style wordmark; no raster asset required."""
    def __init__(self):
        super().__init__(); self.setFixedHeight(58); self.setMinimumWidth(180)

    def paintEvent(self, event):
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont("Nimbus Sans Narrow", 23, QFont.Weight.Black); font.setItalic(True); font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, -1.35)
        path = QPainterPath(); path.addText(6, 36, font, "THZCodeSpair")
        painter.shear(-0.12, 0)
        painter.setPen(QPen(QColor("#030a14"), 6.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)); painter.drawPath(path)
        painter.setPen(QPen(QColor("#55b5ff"), 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)); painter.fillPath(path, QColor("#086bd1")); painter.drawPath(path)
        painter.setPen(QPen(QColor("#9cd5ff"), 1)); painter.drawLine(21, 16, 55, 13); painter.drawLine(73, 14, 111, 11)
        # Tag underline, paint tails and overspray dots.
        painter.setPen(QPen(QColor("#168cff"), 3.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)); painter.drawLine(12, 43, 158, 43); painter.drawLine(144, 47, 180, 38)
        painter.setPen(QPen(QColor("#168cff"), 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)); painter.drawLine(42, 42, 42, 52); painter.drawLine(47, 42, 47, 48); painter.drawLine(128, 42, 128, 50)
        painter.setPen(Qt.PenStyle.NoPen); painter.setBrush(QColor("#2b9cff"))
        for x, y, r in ((4, 16, 2), (10, 9, 1), (175, 16, 2), (181, 25, 1), (164, 6, 1), (30, 54, 1)):
            painter.drawEllipse(x, y, r * 2, r * 2)


class AnalyzerThread(QThread):
    progress = Signal(int, str)
    ready = Signal(object)
    failed = Signal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.ready.emit(analyze_file(self.path, self.progress.emit))
        except Exception as exc:
            self.failed.emit(str(exc))


class DropZone(QFrame):
    selected = Signal(str)

    def __init__(self, language: str = "tr"):
        super().__init__()
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 34, 28, 34)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon = QLabel("⇩")
        icon.setObjectName("dropIcon")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        words = I18N[language]
        title = QLabel(words["drop"])
        title.setObjectName("dropTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note = QLabel(words["drop_note"])
        note.setObjectName("muted")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button = QPushButton(words["choose"])
        button.setObjectName("primary")
        button.clicked.connect(self.pick_file)
        row = QHBoxLayout(); row.addStretch(); row.addWidget(button); row.addStretch()
        layout.addWidget(icon); layout.addSpacing(5); layout.addWidget(title); layout.addWidget(note); layout.addSpacing(14); layout.addLayout(row)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.pick_file()

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Analiz edilecek dosyayı seç")
        if path:
            self.selected.emit(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls() and len(event.mimeData().urls()) == 1:
            event.acceptProposedAction()
            self.setProperty("active", True); self.style().polish(self)

    def dragLeaveEvent(self, event):
        self.setProperty("active", False); self.style().polish(self)

    def dropEvent(self, event: QDropEvent):
        self.setProperty("active", False); self.style().polish(self)
        path = event.mimeData().urls()[0].toLocalFile()
        if Path(path).is_file():
            self.selected.emit(path)


class MetricCard(QFrame):
    def __init__(self, title: str, value: str = "—"):
        super().__init__(); self.setObjectName("card")
        layout = QVBoxLayout(self); layout.setContentsMargins(18, 15, 18, 15)
        label = QLabel(title.upper()); label.setObjectName("eyebrow")
        self.value = QLabel(value); self.value.setObjectName("metric")
        self.value.setWordWrap(True)
        layout.addWidget(label); layout.addWidget(self.value); layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("THZCodeSpair File Inspector")
        self.resize(1240, 790)
        self.setMinimumSize(980, 650)
        self.settings = QSettings("THZCodeSpair", "FileInspector")
        self.language = self.settings.value("language", "tr")
        if self.language not in I18N: self.language = "tr"
        self.worker: AnalyzerThread | None = None
        self.current_result: AnalysisResult | None = None
        self.history = HistoryStore()
        root = QWidget(); self.setCentralWidget(root)
        shell = QHBoxLayout(root); shell.setContentsMargins(0, 0, 0, 0); shell.setSpacing(0)
        shell.addWidget(self.sidebar())
        self.stack = QStackedWidget(); shell.addWidget(self.stack, 1)
        self.stack.addWidget(self.home_page())
        self.stack.addWidget(self.result_page())
        self.stack.addWidget(self.history_page())
        self.stack.addWidget(self.rules_page())

    def t(self, key: str) -> str:
        return I18N[self.language].get(key, key)

    def change_language(self, language: str):
        if language == self.language: return
        self.settings.setValue("language", language)
        self.replacement_window = MainWindow(); self.replacement_window.show(); self.close()

    def sidebar(self):
        frame = QFrame(); frame.setObjectName("sidebar"); frame.setFixedWidth(220)
        layout = QVBoxLayout(frame); layout.setContentsMargins(22, 28, 22, 22)
        logo = GraffitiLogo()
        sub = QLabel(self.t("local")); sub.setObjectName("eyebrow")
        layout.addWidget(logo); layout.addWidget(sub); layout.addSpacing(35)
        for icon, key in [("⌂", "new"), ("▤", "history"), ("◇", "rules")]:
            text = self.t(key)
            button = QPushButton(f"{icon}   {text}"); button.setObjectName("nav")
            if key == "new": button.setProperty("selected", True); button.clicked.connect(lambda: self.stack.setCurrentIndex(0))
            elif key == "history": button.clicked.connect(self.open_history)
            else: button.clicked.connect(lambda: self.stack.setCurrentIndex(3))
            layout.addWidget(button)
        layout.addStretch()
        safe = QLabel(self.t("safe")); safe.setObjectName("safe")
        layout.addWidget(safe)
        return frame

    def home_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(48, 38, 48, 38)
        top = QHBoxLayout(); title_col = QVBoxLayout()
        title = QLabel(self.t("heading")); title.setObjectName("hero")
        subtitle = QLabel(self.t("subheading")); subtitle.setObjectName("subtitle")
        title_col.addWidget(title); title_col.addWidget(subtitle); top.addLayout(title_col); top.addStretch()
        language_label = QLabel(self.t("language")); language_label.setObjectName("eyebrow")
        language = QComboBox(); language.setObjectName("languageSelect"); language.addItem("Türkçe", "tr"); language.addItem("English", "en"); language.setCurrentIndex(0 if self.language == "tr" else 1); language.currentIndexChanged.connect(lambda: self.change_language(language.currentData()))
        language_box = QVBoxLayout(); language_box.addWidget(language_label); language_box.addWidget(language); top.addLayout(language_box)
        layout.addLayout(top); layout.addSpacing(30)
        self.drop = DropZone(self.language); self.drop.selected.connect(self.start_analysis); layout.addWidget(self.drop)
        layout.addSpacing(22)
        caps = QGridLayout(); caps.setSpacing(14)
        for i, (icon, head, text) in enumerate([
            ("#", self.t("crypto"), self.t("crypto_d")),
            ("⌁", self.t("structure"), self.t("structure_d")),
            ("⚑", self.t("risk"), self.t("risk_d")),
        ]):
            card = QFrame(); card.setObjectName("miniCard"); box = QVBoxLayout(card)
            h = QLabel(f"{icon}  {head}"); h.setObjectName("miniTitle"); d = QLabel(text); d.setObjectName("muted"); d.setWordWrap(True)
            box.addWidget(h); box.addWidget(d); caps.addWidget(card, 0, i)
        layout.addLayout(caps); layout.addStretch()
        self.progress_frame = QFrame(); self.progress_frame.setObjectName("progressPanel"); self.progress_frame.hide()
        p = QVBoxLayout(self.progress_frame); self.progress_text = QLabel("Hazırlanıyor"); self.progress = QProgressBar(); self.progress.setTextVisible(False); p.addWidget(self.progress_text); p.addWidget(self.progress)
        layout.addWidget(self.progress_frame)
        return page

    def result_page(self):
        outer = QWidget(); layout = QVBoxLayout(outer); layout.setContentsMargins(38, 28, 38, 28)
        header = QHBoxLayout(); back = QPushButton(self.t("back")); back.setObjectName("secondary"); back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        export = QPushButton(self.t("export")); export.setObjectName("secondary"); export.clicked.connect(self.export_report)
        header.addWidget(back); header.addWidget(export); header.addStretch(); self.path_label = QLabel(); self.path_label.setObjectName("muted"); header.addWidget(self.path_label)
        layout.addLayout(header); layout.addSpacing(16)
        self.report_title = QLabel("Analiz raporu"); self.report_title.setObjectName("pageTitle"); layout.addWidget(self.report_title)
        self.report_subtitle = QLabel(); self.report_subtitle.setObjectName("subtitle"); layout.addWidget(self.report_subtitle); layout.addSpacing(16)
        metrics = QHBoxLayout(); metrics.setSpacing(12)
        self.risk_card = MetricCard(self.t("risk_score")); self.type_card = MetricCard(self.t("file_type")); self.size_card = MetricCard(self.t("size")); self.entropy_card = MetricCard(self.t("entropy"))
        for card in (self.risk_card, self.type_card, self.size_card, self.entropy_card): metrics.addWidget(card, 1)
        layout.addLayout(metrics); layout.addSpacing(16)
        self.tabs = QTabWidget(); self.tabs.setDocumentMode(True)
        self.findings_area = QWidget(); self.findings_layout = QVBoxLayout(self.findings_area); self.findings_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        findings_scroll = QScrollArea(); findings_scroll.setWidgetResizable(True); findings_scroll.setWidget(self.findings_area)
        self.tabs.addTab(findings_scroll, self.t("findings"))
        self.details_table = QTableWidget(0, 2); self.details_table.setHorizontalHeaderLabels(["Alan", "Değer"]); self.details_table.horizontalHeader().setStretchLastSection(True); self.details_table.verticalHeader().hide()
        self.tabs.addTab(self.details_table, self.t("details"))
        self.indicators_text = QTextEdit(); self.indicators_text.setReadOnly(True); self.tabs.addTab(self.indicators_text, self.t("indicators"))
        self.strings_text = QTextEdit(); self.strings_text.setReadOnly(True); self.tabs.addTab(self.strings_text, self.t("strings"))
        layout.addWidget(self.tabs, 1)
        return outer

    def history_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(38, 32, 38, 32)
        top = QHBoxLayout(); title = QLabel(self.t("history_title")); title.setObjectName("pageTitle")
        clear = QPushButton(self.t("clear")); clear.setObjectName("secondary"); clear.clicked.connect(self.clear_history)
        top.addWidget(title); top.addStretch(); top.addWidget(clear); layout.addLayout(top)
        note = QLabel(self.t("history_note")); note.setObjectName("subtitle"); layout.addWidget(note); layout.addSpacing(16)
        self.history_table = QTableWidget(0, 6); self.history_table.setHorizontalHeaderLabels(["Tarih", "Dosya", "Tür", "Skor", "Sonuç", "SHA-256"])
        self.history_table.horizontalHeader().setStretchLastSection(True); self.history_table.verticalHeader().hide(); self.history_table.setAlternatingRowColors(True)
        layout.addWidget(self.history_table, 1); return page

    def rules_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(38, 32, 38, 32)
        title = QLabel(self.t("rules_title")); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel(self.t("rules_note")); note.setObjectName("subtitle"); layout.addWidget(note); layout.addSpacing(18)
        rules = [("Suspicious_PowerShell_Downloader", "PowerShell indirme ve kod çalıştırma dizileri", "YÜKSEK"), ("Suspicious_Process_Injection_APIs", "Windows işlem enjeksiyonu API zinciri", "YÜKSEK"), ("Suspicious_Persistence_RunKey", "Windows başlangıç kalıcılığı kayıt anahtarı", "ORTA")]
        for name, detail, severity in rules:
            row = QFrame(); row.setObjectName("finding"); box = QHBoxLayout(row); text = QVBoxLayout()
            head = QLabel(name); head.setObjectName("findingTitle"); desc = QLabel(detail); desc.setObjectName("muted")
            badge = QLabel(severity); badge.setObjectName("status"); text.addWidget(head); text.addWidget(desc); box.addLayout(text, 1); box.addWidget(badge); layout.addWidget(row)
        layout.addStretch(); return page

    def start_analysis(self, path: str):
        if self.worker and self.worker.isRunning(): return
        self.progress_frame.show(); self.progress.setValue(2); self.progress_text.setText(Path(path).name)
        self.worker = AnalyzerThread(path)
        self.worker.progress.connect(lambda value, text: (self.progress.setValue(value), self.progress_text.setText(text)))
        self.worker.ready.connect(self.show_result); self.worker.failed.connect(self.show_error); self.worker.start()

    def show_result(self, result: AnalysisResult):
        self.current_result = result
        try: self.history.add(result)
        except Exception: pass
        self.progress_frame.hide(); self.path_label.setText(result.path); self.report_title.setText(result.name)
        self.report_subtitle.setText(self.t("completed"))
        verdict = result.verdict if self.language == "tr" else ("High risk" if result.score >= 70 else "Suspicious" if result.score >= 40 else "Caution" if result.score >= 15 else "Low risk")
        self.risk_card.value.setText(f"{result.score}/100\n{verdict}")
        color = "#ff667a" if result.score >= 70 else "#ffb454" if result.score >= 40 else ACCENT
        self.risk_card.value.setStyleSheet(f"color:{color}")
        self.type_card.value.setText(result.mime); self.size_card.value.setText(human_size(result.size)); self.entropy_card.value.setText(f"{result.entropy:.2f} / 8.00")
        while self.findings_layout.count():
            item = self.findings_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        for finding in result.findings:
            row = QFrame(); row.setObjectName("finding"); box = QHBoxLayout(row)
            colors = {"high": "#ff667a", "medium": "#ffb454", "info": ACCENT}
            mark = QLabel("●"); mark.setStyleSheet(f"color:{colors.get(finding.severity, MUTED)};font-size:16px")
            text = QVBoxLayout(); head = QLabel(finding.title); head.setObjectName("findingTitle"); detail = QLabel(finding.detail); detail.setObjectName("muted"); detail.setWordWrap(True)
            text.addWidget(head); text.addWidget(detail); box.addWidget(mark); box.addLayout(text, 1); self.findings_layout.addWidget(row)
        rows = {"Dosya adı": result.name, "Konum": result.path, "Tür": result.file_type, "MIME": result.mime, "Boyut": f"{result.size:,} bayt", **result.timestamps, **result.hashes, **result.metadata}
        self.details_table.setRowCount(len(rows))
        for i, (key, value) in enumerate(rows.items()): self.details_table.setItem(i, 0, QTableWidgetItem(key)); self.details_table.setItem(i, 1, QTableWidgetItem(str(value)))
        self.details_table.resizeRowsToContents()
        blocks = []
        for kind, values in result.indicators.items(): blocks.append(f"{kind.upper()} ({len(values)})\n" + ("\n".join(values) if values else "—"))
        if result.archive_entries: blocks.append("ARŞİV İÇERİĞİ\n" + "\n".join(result.archive_entries))
        self.indicators_text.setPlainText("\n\n".join(blocks)); self.strings_text.setPlainText("\n".join(result.strings)); self.stack.setCurrentIndex(1)

    def open_history(self):
        rows = self.history.list()
        self.history_table.setRowCount(len(rows))
        for r, values in enumerate(rows):
            shown = [values[0].replace("T", " ")[:19], values[1], values[2], str(values[3]), values[4], values[5]]
            for c, value in enumerate(shown): self.history_table.setItem(r, c, QTableWidgetItem(value))
        self.history_table.resizeRowsToContents(); self.stack.setCurrentIndex(2)

    def clear_history(self):
        answer = QMessageBox.question(self, "Geçmişi temizle", "Tüm analiz geçmişi kalıcı olarak silinsin mi?")
        if answer == QMessageBox.StandardButton.Yes: self.history.clear(); self.open_history()

    def export_report(self):
        if not self.current_result: return
        suggested = str(Path.home() / f"{Path(self.current_result.name).stem}-thzcodespair-report.html")
        path, selected = QFileDialog.getSaveFileName(self, "Raporu kaydet", suggested, "HTML raporu (*.html);;JSON raporu (*.json)")
        if path:
            if selected.startswith("JSON") or path.lower().endswith(".json"): write_json(self.current_result, path)
            else: write_html(self.current_result, path)
            self.notice("Rapor kaydedildi.")

    def show_error(self, message: str):
        self.progress_frame.hide(); QMessageBox.critical(self, "Analiz tamamlanamadı", message)

    def notice(self, message: str): QMessageBox.information(self, "THZCodeSpair", message)


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB": return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


STYLE = f"""
* {{ font-family: Inter, 'Noto Sans', sans-serif; color:{TEXT}; font-size:13px; }}
QMainWindow, QWidget {{ background:{BG}; }}
QLabel {{ background:transparent; }}
#sidebar {{ background:#0e131a; border-right:1px solid {BORDER}; }}
#logo {{ color:white; font-size:20px; font-weight:800; letter-spacing:1px; }}
#eyebrow {{ color:{MUTED}; font-size:10px; font-weight:700; letter-spacing:1.5px; }}
#nav {{ text-align:left; background:transparent; border:0; border-radius:8px; padding:11px 12px; color:{MUTED}; }}
#nav:hover, #nav[selected="true"] {{ background:{PANEL_2}; color:white; }}
#safe {{ color:{ACCENT}; background:#101d1b; border:1px solid #21463b; border-radius:10px; padding:14px; font-size:11px; }}
#hero {{ font-size:32px; font-weight:800; color:white; }} #pageTitle {{ font-size:26px; font-weight:800; }}
#subtitle, #muted {{ color:{MUTED}; }} #status {{ color:{ACCENT}; background:#11221e; border:1px solid #244d40; padding:8px 12px; border-radius:15px; font-size:10px; font-weight:700; }}
#dropZone {{ background:{PANEL}; border:1px dashed #3c4a5d; border-radius:16px; }} #dropZone:hover, #dropZone[active="true"] {{ border:1px solid {ACCENT}; background:#111d1d; }}
#dropIcon {{ color:{ACCENT}; font-size:45px; font-weight:300; }} #dropTitle {{ font-size:19px; font-weight:700; }}
#primary {{ background:{ACCENT}; color:#07110e; border:0; border-radius:8px; padding:10px 22px; font-weight:800; }} #primary:hover {{ background:#72e6bb; }}
#secondary {{ background:{PANEL_2}; border:1px solid {BORDER}; border-radius:8px; padding:8px 13px; }}
#languageSelect {{ background:{PANEL_2}; border:1px solid {BORDER}; border-radius:8px; padding:8px 28px 8px 11px; min-width:130px; }}
#languageSelect::drop-down {{ border:0; width:24px; }}
#miniCard, #card, #finding, #progressPanel {{ background:{PANEL}; border:1px solid {BORDER}; border-radius:12px; }} #miniTitle {{ font-weight:700; font-size:14px; }}
#metric {{ font-size:16px; font-weight:750; color:white; }} #findingTitle {{ font-weight:750; font-size:14px; }}
QProgressBar {{ background:#1a222d; border:0; border-radius:3px; height:6px; }} QProgressBar::chunk {{ background:{ACCENT}; border-radius:3px; }}
QTabWidget::pane {{ background:{PANEL}; border:1px solid {BORDER}; border-radius:8px; top:-1px; }} QTabBar::tab {{ color:{MUTED}; background:transparent; padding:11px 17px; }} QTabBar::tab:selected {{ color:{ACCENT}; border-bottom:2px solid {ACCENT}; }}
QScrollArea, QTextEdit, QTableWidget {{ background:{PANEL}; border:0; }} QHeaderView::section {{ background:{PANEL_2}; color:{MUTED}; border:0; padding:9px; }} QTableWidget::item {{ border-bottom:1px solid {BORDER}; padding:6px; }}
QScrollBar:vertical {{ background:transparent; width:9px; }} QScrollBar::handle:vertical {{ background:#344052; border-radius:4px; min-height:30px; }}
"""


def launch() -> int:
    app = QApplication(sys.argv); app.setApplicationName("THZCodeSpair File Inspector"); app.setOrganizationName("THZCodeSpair")
    palette = QPalette(); palette.setColor(QPalette.ColorRole.Window, QColor(BG)); palette.setColor(QPalette.ColorRole.WindowText, QColor(TEXT)); app.setPalette(palette); app.setStyleSheet(STYLE)
    window = MainWindow(); window.show(); return app.exec()


if __name__ == "__main__":
    raise SystemExit(launch())
