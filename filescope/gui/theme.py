from __future__ import annotations

DARK_QSS = r"""
QWidget {
    background-color: #07111f;
    color: #e8f1fb;
    font-family: "Segoe UI";
    font-size: 10pt;
}
QMainWindow, QDialog { background-color: #07111f; }
QToolBar {
    background: #0b1829;
    border: none;
    border-bottom: 1px solid #1b3048;
    spacing: 8px;
    padding: 8px 12px;
}
QToolButton, QPushButton {
    background: #13263b;
    border: 1px solid #23435f;
    border-radius: 7px;
    padding: 7px 13px;
    min-height: 18px;
}
QToolButton:hover, QPushButton:hover { background: #18324c; border-color: #2b7897; }
QToolButton:pressed, QPushButton:pressed { background: #0f2032; }
QPushButton#accentButton { background: #08a9ca; border-color: #16c3df; color: #00131b; font-weight: 700; }
QPushButton#dangerButton { background: #47202b; border-color: #87394b; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {
    background: #0c1a2a;
    border: 1px solid #213a53;
    border-radius: 7px;
    padding: 7px;
    selection-background-color: #087f9c;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border-color: #14b8d4; }
QListWidget#navigation {
    background: #081523;
    border: none;
    border-right: 1px solid #1b3048;
    outline: none;
    padding: 10px 7px;
}
QListWidget#navigation::item {
    color: #9fb1c5;
    border-radius: 7px;
    padding: 8px 10px;
    margin: 1px 0;
}
QListWidget#navigation::item:hover { background: #10253a; color: #eaf7ff; }
QListWidget#navigation::item:selected { background: #0d4358; color: #bff7ff; border-left: 3px solid #17c3de; }
QTabWidget::pane { border: 0; }
QTabBar::tab {
    background: #0b1829;
    color: #9fb1c5;
    padding: 10px 18px;
    border-right: 1px solid #1b3048;
}
QTabBar::tab:selected { background: #10243a; color: #e9faff; border-top: 2px solid #14bad7; }
QTreeWidget, QTableWidget, QTableView {
    background: #0a1726;
    alternate-background-color: #0d1c2d;
    border: 1px solid #1d344c;
    border-radius: 8px;
    gridline-color: #173047;
    selection-background-color: #10566d;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #102238;
    color: #bed0e2;
    border: none;
    border-right: 1px solid #203b55;
    border-bottom: 1px solid #203b55;
    padding: 8px;
    font-weight: 600;
}
QScrollBar:vertical { background: #081421; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #25465f; border-radius: 5px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #081421; height: 12px; }
QScrollBar::handle:horizontal { background: #25465f; border-radius: 5px; min-width: 28px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QGroupBox {
    border: 1px solid #1d344c;
    border-radius: 10px;
    margin-top: 12px;
    padding: 14px;
    font-weight: 600;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; color: #b8eaf4; }
QLabel#pageTitle { font-size: 20pt; font-weight: 700; color: #f4f9ff; }
QLabel#pageSubtitle { color: #8fa5ba; }
QLabel#metricValue { font-size: 24pt; font-weight: 800; color: #45d0e8; }
QLabel#metricLabel { color: #8fa5ba; }
QFrame#card { background: #0d1d2f; border: 1px solid #1e3852; border-radius: 12px; }
QFrame#headerPanel { background: #0b1d31; border-bottom: 1px solid #1b3048; }
QProgressBar { border: 1px solid #204059; border-radius: 5px; text-align: center; background: #081523; }
QProgressBar::chunk { background: #10b7d2; border-radius: 4px; }
QStatusBar { background: #091625; color: #95a9bd; border-top: 1px solid #1b3048; }
QMenuBar { background: #0b1829; }
QMenuBar::item:selected, QMenu::item:selected { background: #0d4a60; }
QMenu { background: #0d1a2a; border: 1px solid #28445d; }
QToolTip { background: #11263b; color: white; border: 1px solid #2c5f7c; padding: 5px; }
"""

LIGHT_QSS = r"""
QWidget { background:#f4f7fb; color:#172638; font-family:"Segoe UI"; font-size:10pt; }
QMainWindow,QDialog{background:#f4f7fb} QToolBar{background:#ffffff;border:none;border-bottom:1px solid #d7e1ec;padding:8px 12px;spacing:8px}
QToolButton,QPushButton{background:#eef4f9;border:1px solid #c9d7e4;border-radius:7px;padding:7px 13px;min-height:18px}
QToolButton:hover,QPushButton:hover{background:#e3f5f9;border-color:#3a9db2} QPushButton#accentButton{background:#0fa8c5;border-color:#0b8fa8;color:white;font-weight:700}
QLineEdit,QComboBox,QSpinBox,QPlainTextEdit,QTextEdit{background:white;border:1px solid #c6d5e3;border-radius:7px;padding:7px;selection-background-color:#73c9da}
QListWidget#navigation{background:#ffffff;border:none;border-right:1px solid #d7e1ec;padding:10px 7px;outline:none} QListWidget#navigation::item{color:#526579;border-radius:7px;padding:8px 10px;margin:1px 0} QListWidget#navigation::item:selected{background:#dff5f9;color:#075d71;border-left:3px solid #0fa8c5}
QTabWidget::pane{border:0} QTabBar::tab{background:#eaf0f6;color:#526579;padding:10px 18px;border-right:1px solid #d7e1ec} QTabBar::tab:selected{background:white;color:#172638;border-top:2px solid #0fa8c5}
QTreeWidget,QTableWidget,QTableView{background:white;alternate-background-color:#f7f9fc;border:1px solid #d5e0eb;border-radius:8px;gridline-color:#e1e8ef;selection-background-color:#cdeef4;selection-color:#172638} QHeaderView::section{background:#eaf1f7;color:#33495f;border:none;border-right:1px solid #d5e0eb;border-bottom:1px solid #d5e0eb;padding:8px;font-weight:600}
QFrame#card{background:white;border:1px solid #d7e1ec;border-radius:12px} QFrame#headerPanel{background:white;border-bottom:1px solid #d7e1ec} QLabel#pageTitle{font-size:20pt;font-weight:700} QLabel#pageSubtitle,QLabel#metricLabel{color:#64798f} QLabel#metricValue{font-size:24pt;font-weight:800;color:#0d94ae}
QGroupBox{border:1px solid #d5e0eb;border-radius:10px;margin-top:12px;padding:14px;font-weight:600} QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 5px;color:#1a6070}
QStatusBar{background:white;color:#526579;border-top:1px solid #d7e1ec} QMenuBar,QMenu{background:white} QMenuBar::item:selected,QMenu::item:selected{background:#dff5f9}
"""
