from PySide6.QtWidgets import QWidget,QMainWindow,QApplication,QTextEdit,QLabel,QPushButton,QVBoxLayout,QHBoxLayout,QLineEdit,QSpinBox
from PySide6.QtCore import Signal
class Guiwindow(QWidget):
    #Recvmessage=Signal(str)
    def __init__(self):
        super().__init__()
        self.Mainlayout=QVBoxLayout()
        self.ButtonLayout=QVBoxLayout()
        self.target_file_path = None
        self.setAcceptDrops(True)
        self.setGeometry(0,0,800,800)
        self.AIbutton=QPushButton()
        self.AIbutton.setText("AI分析")
        self.EnterButton=QPushButton()
        self.EnterButton.setText("发送")
        self.LineEdit=QLineEdit()
        self.LineEdit.setPlaceholderText("目标IP 端口")
        self.IterationSpinBox = QSpinBox()
        self.IterationSpinBox.setRange(1, 50)          # 最小1次，最大50次
        self.IterationSpinBox.setValue(15)             # 默认15次（你原来的硬编码值）
        self.IterationSpinBox.setPrefix("循环次数: ")   # 显示前缀
        self.IterationSpinBox.setToolTip("AI测试EXP的最大尝试次数，建议15-20次")
        #self.EnterButton.clicked.connect(self.sendMessagefuc)
        self.Enterlayout=QHBoxLayout()
        self.MessageBox=QTextEdit()
        self.Entertext=QTextEdit()
        self.MessageBox.setAcceptDrops(False)
        self.Entertext.setAcceptDrops(False)
        self.MessageBox.setReadOnly(True)
        self.Entertext.setPlaceholderText("可拖拽文件")
        self.Entertext.setFixedHeight(80)
        self.Entertext.setFixedWidth(650)
        self.Mainlayout.addWidget(self.MessageBox)
        self.Enterlayout.addWidget(self.Entertext)
        self.ButtonLayout.addWidget(self.AIbutton)
        self.ButtonLayout.addWidget(self.EnterButton)
        self.ButtonLayout.addWidget(self.LineEdit)
        self.ButtonLayout.addWidget(self.IterationSpinBox)
        self.Enterlayout.addLayout(self.ButtonLayout)
        self.Mainlayout.addLayout(self.Enterlayout)
        self.setLayout(self.Mainlayout)
        #self.Recvmessage.connect(self.MessageBox.append)
    '''def sendMessagefuc(self):
        text=self.Entertext.toPlainText().strip()           
        self.Recvmessage.emit(text)
        if text != '\n' and text != '':
            self.Entertext.clear()
            self.MessageBox.append("[AI思考中]....")'''
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
             event.accept()     
        else:
            event.ignore()  
    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.target_file_path=file_path
if __name__ == '__main__':
    app=QApplication([])
    mywindow=Guiwindow()
    mywindow.show()
    app.exec()    