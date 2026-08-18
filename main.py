from analyze import Analyzewindow
from login import loginWindow
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
class MainWindow(Analyzewindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pwn")
class SubWindow(loginWindow):
    def __init__(self):
        super().__init__()
        self.setWindowModality(Qt.ApplicationModal)
if __name__ == '__main__':
    app=QApplication([])
    MainWindow=MainWindow()
    SubWindow=SubWindow()
    MainWindow.show()
    SubWindow.show()
    app.exec()