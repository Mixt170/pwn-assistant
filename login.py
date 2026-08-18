from PySide6.QtWidgets import QLabel,QWidget,QApplication,QVBoxLayout,QPushButton
from PySide6.QtCore import Qt
class loginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("QWidget { background-color: #ffffff; }")
        self.resize(350, 220)
        self.MainLayout=QVBoxLayout()
        self.MainLayout.setContentsMargins(30, 25, 30, 25)
        self.MainLayout.setSpacing(15)
        self.Label1=QLabel("请确保根目录下已正确配置 .env 文件")
        self.PushButton=QPushButton()
        self.Label1.setStyleSheet("color: #333333; font-size: 15px; font-weight: bold; font-family: 'Microsoft YaHei';")
        self.Label1.setAlignment(Qt.AlignCenter)
        self.Label2=QLabel("API_KEY = DeepSeek_API\nIDA_PATH = xxx/IDA/idat")
        self.Label2.setAlignment(Qt.AlignCenter)
        self.Label2.setStyleSheet(
            """
            QLabel {
            background-color: #f4f5f7;  
            color: #d63384;             
            font-family: Consolas, monospace;
            font-size: 13px;
            border-radius: 8px;         
            padding: 15px;              
            border: 1px solid #e2e8f0; 
            }
            """
            )
        self.PushButton.setText("我已配置完毕")
        self.MainLayout.addWidget(self.Label1)
        self.MainLayout.addWidget(self.Label2)
        self.MainLayout.addSpacing(10)
        self.MainLayout.addWidget(self.PushButton)
        self.setWindowTitle("初始化注意")
        self.setLayout(self.MainLayout)
        self.PushButton.clicked.connect(self.close)
if __name__ == '__main__':
    app=QApplication([])
    loginWindow=loginWindow()
    loginWindow.show()
    app.exec()