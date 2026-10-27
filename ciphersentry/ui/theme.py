"""Shared desktop palette and Qt styles for CipherSentry."""

BACKGROUND = "#0b111b"
SURFACE = "#111d2b"
BORDER = "#223345"
MINT = "#69e3bc"
TEXT = "#eff5fb"
MUTED = "#8fa3b8"

STYLESHEET = """
QWidget {
    color: #eff5fb;
    font-family: "Segoe UI", "DejaVu Sans", sans-serif;
    font-size: 12px;
}
QMainWindow, QWidget#appRoot, QWidget#page, QStackedWidget {
    background: #0b111b;
}
QWidget#sidebar, QFrame#sidebar { background: #0d1522; }
QFrame[card="true"] {
    background: #111d2b;
    border: 1px solid #223345;
    border-radius: 12px;
}
QFrame#hero, QFrame#heroPanel { background: #12282c; border: 1px solid #28483f; border-radius: 12px; }
QFrame#divider { background: #223345; border: 0; max-height: 1px; }
QLabel { background: transparent; border: none; }
QLabel#title { font-size: 27px; font-weight: 700; letter-spacing: -0.5px; }
QLabel#subtitle { color: #8fa3b8; font-size: 12px; }
QLabel#eyebrow { color: #8fa3b8; font-size: 10px; font-weight: 600; letter-spacing: 1.5px; }
QLabel#muted { color: #8fa3b8; }
QLabel#sectionTitle { font-size: 15px; font-weight: 600; }
QLabel#heroTitle { font-size: 20px; font-weight: 600; letter-spacing: -0.3px; }
QLabel#bodyStrong { font-weight: 600; }
QLabel#brand { font-size: 17px; font-weight: 700; letter-spacing: -0.4px; }
QLabel#statusBadge {
    color: #a1e6cf;
    background: #16312e;
    border: 1px solid #26473f;
    border-radius: 10px;
    padding: 5px 10px;
    font-size: 10px;
    font-weight: 500;
}
QLabel#badge {
    color: #69e3bc;
    background: #16352f;
    border: 1px solid #295347;
    border-radius: 11px;
    padding: 4px 9px;
    font-size: 10px;
    font-weight: 600;
}
QPushButton {
    color: #dbe7f3;
    background: #182638;
    border: 1px solid #2a3d52;
    border-radius: 7px;
    padding: 9px 15px;
    font-weight: 600;
    min-height: 17px;
}
QPushButton:hover { background: #213349; border-color: #405b74; }
QPushButton:pressed { background: #0f1c2c; }
QPushButton:focus { border-color: #69e3bc; }
QPushButton:disabled { color: #536579; background: #111b27; border-color: #1d2b3b; }
QPushButton[variant="primary"] { color: #09211b; background: #69e3bc; border-color: #69e3bc; }
QPushButton[variant="primary"]:hover { background: #8aebce; border-color: #8aebce; }
QPushButton[variant="primary"]:pressed { background: #44c99f; }
QPushButton[variant="primary"]:disabled { color: #45685c; background: #203d34; border-color: #203d34; }
QPushButton[variant="secondary"] { background: #152233; border-color: #2c4056; }
QPushButton[variant="danger"] { color: #ffacae; background: #38252c; border-color: #633840; }
QPushButton[variant="danger"]:hover { background: #4c2d35; }
QPushButton[variant="danger"]:disabled { color: #67515a; background: #201c26; border-color: #302631; }
QPushButton[variant="ghost"] { background: transparent; color: #8fa3b8; border: none; padding: 7px 10px; }
QPushButton[variant="ghost"]:hover { color: #eff5fb; background: #172536; }
QPushButton[variant="nav"] {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 7px;
    color: #8fa3b8;
    text-align: left;
    padding: 12px 15px;
    font-weight: 500;
}
QPushButton[variant="nav"]:hover { color: #e5eff7; background: #142233; }
QPushButton[variant="nav"]:checked { color: #69e3bc; background: #16302e; border-color: #24483f; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background: #0d1723;
    border: 1px solid #2a3d52;
    border-radius: 6px;
    padding: 8px 10px;
    color: #dce8f4;
    selection-background-color: #275d50;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border-color: #69e3bc; }
QComboBox::drop-down { border: none; width: 26px; }
QComboBox QAbstractItemView { background: #152233; border: 1px solid #30465e; selection-background-color: #25453f; }
QCheckBox { color: #dce8f4; spacing: 9px; padding: 4px 0; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #42596e; border-radius: 4px; background: #0d1723; }
QCheckBox::indicator:checked { background: #69e3bc; border-color: #69e3bc; }
QCheckBox::indicator:disabled { background: #23322f; border-color: #2c403a; }
QProgressBar { border: none; border-radius: 3px; background: #233246; min-height: 5px; max-height: 5px; text-align: center; }
QProgressBar::chunk { background: #69e3bc; border-radius: 3px; }
QTableWidget, QTableView {
    background: transparent;
    alternate-background-color: #132131;
    border: none;
    border-radius: 0;
    gridline-color: #1e2d3f;
    selection-background-color: #203c3b;
    selection-color: #eff5fb;
    outline: 0;
}
QTableWidget::item, QTableView::item { border-bottom: 1px solid #1e2d3f; padding: 7px 9px; }
QTableWidget::item:selected, QTableView::item:selected { background: #203c3b; }
QHeaderView::section {
    background: #111d2b;
    color: #7f96ad;
    border: none;
    border-bottom: 1px solid #25364a;
    padding: 10px 9px;
    text-align: left;
    font-size: 10px;
    font-weight: 600;
}
QTableCornerButton::section { background: #111d2b; border: none; }
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 7px; margin: 2px 0; }
QScrollBar::handle:vertical { background: #2b4054; border-radius: 3px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #3f5a72; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 7px; margin: 0 2px; }
QScrollBar::handle:horizontal { background: #2b4054; border-radius: 3px; min-width: 30px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QTextEdit, QPlainTextEdit {
    background: #0d1723;
    border: 1px solid #223345;
    border-radius: 7px;
    padding: 9px;
    color: #c9d9e7;
    selection-background-color: #275d50;
}
QTabWidget::pane { border: 1px solid #223345; border-radius: 8px; background: #111d2b; }
QTabBar::tab { background: transparent; padding: 11px 17px; color: #8fa3b8; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #69e3bc; border-bottom-color: #69e3bc; }
QTabBar::tab:hover { background: #152233; }
QStatusBar { background: #0d1522; border-top: 1px solid #1d2b3b; color: #8fa3b8; font-size: 10px; }
QStatusBar::item { border: none; }
QToolTip { color: #e8f1f8; background: #1b2d3e; border: 1px solid #3b5267; padding: 7px; }
QMessageBox, QFileDialog, QDialog { background-color: #111d2b; color: #eff5fb; }
QDialog QTextEdit, QDialog QPlainTextEdit { background-color: #0d1723; color: #c9d9e7; }
QMenu { background: #152233; border: 1px solid #30465e; padding: 5px; }
QMenu::item { padding: 7px 22px; }
QMenu::item:selected { background: #25453f; }
"""
