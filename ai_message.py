from PySide6.QtCore import QThread,Signal
from openai import OpenAI
import os
class MessageThread(QThread):
    log_signal=Signal(str)
    result_signal=Signal(str)
    def __init__(self, content_history):
        super().__init__()
        self.content=content_history
    def run(self):
        api_key = os.getenv('API_KEY')
        try:
            if not api_key:
                self.log_signal.emit('[+] 未找到API_KEY,请检查 .env 文件！')
                return
            client = OpenAI(
                base_url = 'https://api.deepseek.com/v1',
                api_key = api_key
                )
            response = client.chat.completions.create(
                    model='deepseek-v4-flash',
                    messages=self.content,
                    temperature=0.3
                    )
            response_message = response.choices[0].message
            if response_message and response_message.content:
                self.result_signal.emit(response_message.content)
            else:
                self.log_signal.emit("[+] 警告: AI 返回了空文本。")
        except Exception as e:
            self.log_signal.emit(f"Error as {e}")