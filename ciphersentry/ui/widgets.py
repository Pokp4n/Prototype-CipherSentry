"""Small, vector-painted desktop widgets; every plotted value is supplied by the app."""

from __future__ import annotations

from collections import deque
import time

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .theme import BORDER, MINT, MUTED, TEXT


def _path(points: list[tuple[float, float]], close: bool = False) -> QPainterPath:
    shape = QPainterPath(QPointF(*points[0]))
    for point in points[1:]:
        shape.lineTo(QPointF(*point))
    if close:
        shape.closeSubpath()
    return shape


def draw_icon(painter: QPainter, name: str, color: str = MUTED) -> None:
    """Draw a 24 x 24 line icon using the painter's current transform."""
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(color), 1.65, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    if name == "shield":
        painter.drawPath(_path([(12, 2.7), (20, 6), (19.3, 13), (17, 17.5), (12, 21), (7, 17.5), (4.7, 13), (4, 6)], True))
        painter.drawPath(_path([(8.5, 11.7), (11, 14.2), (15.8, 9.3)]))
    elif name == "grid":
        for x, y in [(4, 4), (14, 4), (4, 14), (14, 14)]:
            painter.drawRoundedRect(QRectF(x, y, 6, 6), 1, 1)
    elif name == "activity":
        painter.drawPath(_path([(2.5, 12), (6.7, 12), (9.7, 5), (13.4, 19), (16.8, 10), (19, 12), (21.5, 12)]))
    elif name == "flask":
        painter.drawLine(QPointF(9, 3), QPointF(15, 3))
        painter.drawPath(_path([(10, 3), (10, 10), (4.8, 18.5), (5.8, 21), (18.2, 21), (19.2, 18.5), (14, 10), (14, 3)]))
        painter.drawLine(QPointF(8, 15), QPointF(16, 15))
        painter.drawEllipse(QPointF(11, 18), 0.5, 0.5)
    elif name == "settings":
        painter.drawEllipse(QPointF(12, 12), 6.4, 6.4)
        painter.drawEllipse(QPointF(12, 12), 2.5, 2.5)
        for angle in range(0, 360, 45):
            painter.save()
            painter.translate(12, 12)
            painter.rotate(angle)
            painter.drawLine(QPointF(0, -8), QPointF(0, -10))
            painter.restore()
    elif name == "download":
        painter.drawPath(_path([(12, 3), (12, 15)]))
        painter.drawPath(_path([(7.5, 10.5), (12, 15), (16.5, 10.5)]))
        painter.drawPath(_path([(4, 16), (4, 20), (20, 20), (20, 16)]))
    elif name == "folder":
        painter.drawPath(_path([(3, 7), (3, 19), (21, 19), (21, 7), (12, 7), (10, 4), (3, 4), (3, 7)], True))
        painter.drawLine(QPointF(3, 9), QPointF(21, 9))
    elif name in {"arrow", "chevron"}:
        if name == "arrow":
            painter.drawLine(QPointF(4, 12), QPointF(20, 12))
            painter.drawPath(_path([(15, 7), (20, 12), (15, 17)]))
        else:
            painter.drawPath(_path([(9, 6), (15, 12), (9, 18)]))
    elif name == "play":
        painter.drawPath(_path([(8, 4), (20, 12), (8, 20)], True))
    elif name == "pause":
        painter.drawRoundedRect(QRectF(6, 4, 3.5, 16), 0.8, 0.8)
        painter.drawRoundedRect(QRectF(14.5, 4, 3.5, 16), 0.8, 0.8)
    elif name == "stop":
        painter.drawRoundedRect(QRectF(5, 5, 14, 14), 2, 2)
    elif name == "cpu":
        painter.drawRoundedRect(QRectF(6, 6, 12, 12), 2, 2)
        painter.drawRect(QRectF(9, 9, 6, 6))
        for v in (8, 12, 16):
            painter.drawLine(QPointF(v, 3), QPointF(v, 6))
            painter.drawLine(QPointF(v, 18), QPointF(v, 21))
            painter.drawLine(QPointF(3, v), QPointF(6, v))
            painter.drawLine(QPointF(18, v), QPointF(21, v))
    elif name == "file":
        painter.drawPath(_path([(6, 3), (14, 3), (19, 8), (19, 21), (6, 21)], True))
        painter.drawPath(_path([(14, 3), (14, 8), (19, 8)]))
        painter.drawLine(QPointF(9, 12), QPointF(16, 12))
        painter.drawLine(QPointF(9, 16), QPointF(14, 16))
    elif name == "check":
        painter.drawPath(_path([(5, 12), (10, 17), (19, 7)]))
    else:
        painter.drawEllipse(QPointF(12, 12), 8, 8)
        painter.drawLine(QPointF(12, 7), QPointF(12, 13))
        painter.drawPoint(QPointF(12, 17))


class Icon(QWidget):
    def __init__(self, name: str, size: int = 22, color: str = MUTED, parent: QWidget | None = None):
        super().__init__(parent)
        self.name = name
        self.color = color
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.scale(self.width() / 24, self.height() / 24)
        draw_icon(painter, self.name, self.color)


class ShieldMark(QWidget):
    def __init__(self, size: int = 44, parent: QWidget | None = None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#2b574b"), 1))
        painter.setBrush(QColor("#16382f"))
        painter.drawRoundedRect(QRectF(0.5, 0.5, self.width() - 1, self.height() - 1), 11, 11)
        painter.translate(self.width() * 0.19, self.height() * 0.19)
        painter.scale(self.width() * 0.62 / 24, self.height() * 0.62 / 24)
        draw_icon(painter, "shield", MINT)


class StatCard(QFrame):
    def __init__(self, title: str, value: str, caption: str, icon: str = "activity", parent: QWidget | None = None):
        super().__init__(parent)
        self.setProperty("card", True)
        self.setMinimumHeight(116)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 14)
        layout.setSpacing(7)
        top = QHBoxLayout()
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("eyebrow")
        top.addWidget(self.title_label)
        top.addStretch()
        top.addWidget(Icon(icon, 18, MUTED))
        layout.addLayout(top)
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet("font-size: 28px; font-weight: 650; color: #eff5fb;")
        layout.addWidget(self.value_label)
        self.caption_label = QLabel(caption)
        self.caption_label.setObjectName("muted")
        self.caption_label.setStyleSheet("font-size: 10px; color: #8fa3b8;")
        self.caption_label.setWordWrap(True)
        layout.addWidget(self.caption_label)

    def set_value(self, value: str, caption: str | None = None) -> None:
        self.value_label.setText(value)
        if caption is not None:
            self.caption_label.setText(caption)


class RiskChart(QWidget):
    """A bounded 60-second plot. No placeholder readings are generated."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMinimumHeight(180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.points: deque[tuple[float, int]] = deque(maxlen=2400)
        self.threshold = 75

    def add_point(self, score: int, timestamp: float | None = None) -> None:
        timestamp = time.time() if timestamp is None else timestamp
        self.points.append((timestamp, min(100, max(0, score))))
        while self.points and self.points[0][0] < timestamp - 60:
            self.points.popleft()
        self.update()

    def clear(self) -> None:
        self.points.clear()
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart = QRectF(31, 14, max(1, self.width() - 48), max(1, self.height() - 43))
        font = self.font()
        font.setPixelSize(9)
        painter.setFont(font)
        for level in (0, 25, 50, 75, 100):
            y = chart.bottom() - level / 100 * chart.height()
            painter.setPen(QPen(QColor("#223345"), 1, Qt.PenStyle.DotLine))
            painter.drawLine(QPointF(chart.left(), y), QPointF(chart.right(), y))
            painter.setPen(QColor("#6d859d"))
            painter.drawText(QRectF(0, y - 7, 23, 14), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(level))
        threshold_y = chart.bottom() - self.threshold / 100 * chart.height()
        painter.setPen(QPen(QColor("#735d43"), 1, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(chart.left(), threshold_y), QPointF(chart.right(), threshold_y))
        for fraction, label in [(0, "60s ago"), (0.25, "45s"), (0.5, "30s"), (0.75, "15s"), (1, "Now")]:
            x = chart.left() + chart.width() * fraction
            painter.setPen(QColor("#6d859d"))
            text_rect = QRectF(x - 24, chart.bottom() + 9, 48, 14)
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, label)
        now = time.time()
        samples = [(ts, score) for ts, score in self.points if now - 60 <= ts <= now + 1]
        if not samples:
            painter.setPen(QColor(MUTED))
            font.setPixelSize(11)
            painter.setFont(font)
            painter.drawText(chart, Qt.AlignmentFlag.AlignCenter, "Live risk scores will appear here")
            return
        mapped = [QPointF(chart.left() + (ts - now + 60) / 60 * chart.width(), chart.bottom() - score / 100 * chart.height()) for ts, score in samples]
        painter.save()
        painter.setClipRect(chart.adjusted(-2, -2, 2, 2))
        line = QPainterPath(mapped[0])
        for point in mapped[1:]:
            line.lineTo(point)
        fill = QPainterPath(line)
        fill.lineTo(mapped[-1].x(), chart.bottom())
        fill.lineTo(mapped[0].x(), chart.bottom())
        fill.closeSubpath()
        gradient = QLinearGradient(0, chart.top(), 0, chart.bottom())
        gradient.setColorAt(0, QColor(105, 227, 188, 70))
        gradient.setColorAt(1, QColor(105, 227, 188, 1))
        painter.fillPath(fill, gradient)
        painter.setPen(QPen(QColor(MINT), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(line)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(105, 227, 188, 35))
        painter.drawEllipse(mapped[-1], 7, 7)
        painter.setBrush(QColor(MINT))
        painter.drawEllipse(mapped[-1], 3, 3)
        painter.restore()


class RiskGauge(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMinimumSize(130, 130)
        self.setMaximumSize(180, 180)
        self.score = 0
        self.level = "No evidence"

    def set_score(self, score: int, level: str) -> None:
        self.score = max(0, min(100, score))
        self.level = level
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        size = min(self.width(), self.height()) - 20
        circle = QRectF((self.width() - size) / 2, (self.height() - size) / 2, size, size)
        painter.setPen(QPen(QColor("#25364a"), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(circle, 90 * 16, -360 * 16)
        color = "#ff8d96" if self.score >= getattr(self, "high_threshold", 75) else "#efbd77" if self.score >= getattr(self, "uncertain_threshold", 40) else MINT
        painter.setPen(QPen(QColor(color), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        if self.score:
            painter.drawArc(circle, 90 * 16, -int(360 * 16 * self.score / 100))
        font = self.font()
        font.setPixelSize(33)
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.setPen(QColor(TEXT))
        painter.drawText(circle.adjusted(0, -10, 0, -10), Qt.AlignmentFlag.AlignCenter, str(self.score))
        font.setPixelSize(10)
        font.setWeight(QFont.Weight.Normal)
        painter.setFont(font)
        painter.setPen(QColor(color if self.score else MUTED))
        painter.drawText(circle.adjusted(0, 42, 0, 0), Qt.AlignmentFlag.AlignCenter, self.level.upper())


class SignalMeter(QWidget):
    def __init__(self, name: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        top = QHBoxLayout()
        self.name_label = QLabel(name)
        self.name_label.setStyleSheet("font-size: 11px; color: #c3d3e2;")
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet("font-size: 10px; color: #8fa3b8;")
        top.addWidget(self.name_label)
        top.addStretch()
        top.addWidget(self.value_label)
        layout.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        layout.addWidget(self.bar)

    def set_signal(self, points: int, maximum: int, detail: str, available: bool = True, value: str = "") -> None:
        self.bar.setRange(0, max(1, maximum))
        self.bar.setValue(max(0, min(points, maximum)))
        self.value_label.setText("Unavailable" if not available else "Descriptive" if maximum == 0 else f"{points} / {maximum}")
        if value:
            detail = value + "\n" + detail
        self.setToolTip(detail)
        self.setAccessibleDescription(detail)


def section_header(title: str, subtitle: str = "") -> QWidget:
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(5)
    title_label = QLabel(title)
    title_label.setObjectName("sectionTitle")
    layout.addWidget(title_label)
    if subtitle:
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("subtitle")
        subtitle_label.setWordWrap(True)
        layout.addWidget(subtitle_label)
    return widget
