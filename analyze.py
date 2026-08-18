import re
import os
from dotenv import load_dotenv
load_dotenv()
from PySide6.QtWidgets import QWidget,QApplication
from pwn import*
from gui import Guiwindow
from ai_agent import AIThread
from ai_message import MessageThread
from tools import run_cmd
from google import genai
context.log_level = 'error'
IDA_path=os.getenv("IDA_PATH")
api_key=os.getenv("API_KEY")
#client=genai.Client(api_key = api_key)
class Analyzewindow(Guiwindow):
    def __init__(self):
        super().__init__()
        self.AIbutton.clicked.connect(self.check_and_run_ai)
        self.EnterButton.clicked.connect(self.Messagefuc)
        self.content_history = []
        self.target_file_path = None
        self.target_libc_path = None
        self.analyze_result = None
    def dropEvent(self, event):
        
        super().dropEvent(event)
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.target_file_path = file_path
            self.MessageBox.append(f"[+] 🎯 成功装载主程序: {file_path}")
            if self.target_file_path:
                self.analyze(self.target_file_path)
    def analyze(self,file_path):
        
        try:
            elf=ELF(file_path)
            cmd=f'checksec "{file_path}"' 
            self.analyze_result=run_cmd(cmd) + '\n'
            cmd= f'ldd "{file_path}"'
            ldd_result=run_cmd(cmd)
            match = re.search(r'libc\.so.*?=>\s+([^\s]+)', ldd_result)
            if match:
                self.target_libc_path = match.group(1)
                libc = ELF(self.target_libc_path)
                rop = ROP(libc)
                system_offset=libc.symbols['system']
                bin_sh_offset=next(libc.search(b'/bin/sh'))
                read_offset=libc.symbols['read']
                write_offset=libc.symbols['write']
                open_offset=libc.symbols['open']
                execve_offset=libc.symbols['execve']
                self.analyze_result+=f'\n[+][Libc偏移][{self.target_libc_path}]\n'
                self.analyze_result+=f'    system : {hex(system_offset)}\n'
                self.analyze_result+=f'    bin_sh : {hex(bin_sh_offset)}\n'
                self.analyze_result+=f'    execve : {hex(execve_offset)}\n'
                self.analyze_result+=f'    read : {hex(read_offset)}\n'
                self.analyze_result+=f'    write : {hex(write_offset)}\n'
                self.analyze_result+=f'    open : {hex(open_offset)}\n'
                if elf.arch == 'amd64':
                    libc_pop_rdi = rop.find_gadget(['pop rdi', 'ret'])
                    libc_ret = rop.find_gadget(['ret'])
                    self.analyze_result+=f'    pop rdi;ret : {hex(libc_pop_rdi.address)}\n'
                    self.analyze_result+=f'    ret : {hex(libc_ret.address)}\n'
                elif elf.arch == 'i386':
                    libc_pop_ebx = rop.find_gadget(['pop ebx', 'ret'])
                    self.analyze_result += f"  pop ebx;ret : {hex(libc_pop_ebx.address)}\n"
            rop2 = ROP(elf)
            self.analyze_result+=f'\n[+][POP gadgets]\n'
            count = 0
            for addr,gadget in rop2.gadgets.items():
                instructions = " ; ".join(gadget.insns)
                if 'pop' in instructions or "leave" in instructions or instructions == "ret":
                    self.analyze_result += f"    {instructions} : {hex(addr)}\n"
                    count+=1
                    if count>=20:
                        break
            self.analyze_result += f"\n[+][主程序核心 GOT 表]\n"
            key_functions = ['puts', 'printf', 'read', 'write', 'setvbuf', 'fflush', 'atoi']
            got_found = False
            for func in key_functions:
                if func in elf.got:
                    self.analyze_result += f"    {func} : {hex(elf.got[func])}\n"
                    got_found=True
            if not got_found:
                self.analyze_result += "无常规危险GOT表项\n"
            self.analyze_result += f"\n[+][主程序可写内存区域]\n"
            try:
                bss_addr=elf.bss()
                self.analyze_result+=f"    bss段 : {hex(bss_addr)}\n"
            except Exception:
                pass
            self.analyze_result += "\n[+]正在尝试反编译\n"
            QApplication.processEvents()
            try:
                if os.path.exists("vuln_c_code.txt"):
                    os.remove("vuln_c_code.txt")
                script_path = os.path.abspath("ida_dump.py")
                cmd = f'{IDA_path} -A -c -S"{script_path}" "{file_path}"'
                ida_log = run_cmd(cmd)
                QApplication.processEvents()
                base_dir = os.path.dirname(file_path)
                base_name = os.path.basename(file_path)
                garbage_extensions = ['.i64', '.id0', '.id1', '.nam', '.til', '.bak', '.id2']
                for ext in garbage_extensions:
                    garbage_file = os.path.join(base_dir, base_name + ext)
                    if os.path.exists(garbage_file):
                        try:
                            os.remove(garbage_file)
                        except Exception:
                            pass
                if os.path.exists("vuln_c_code.txt"):
                    with open("vuln_c_code.txt", "r", encoding="utf-8") as f:
                        self.vuln_c_code = f.read()
                    if self.vuln_c_code.strip():
                        self.analyze_result+="[+]IDA 运行成功\n"
                        #print(self.vuln_c_code.strip())
                else:
                    self.analyze_result+="[+]IDA 运行失败，未生成代码文件\n"
                    self.analyze_result+=f"[+]调试日志: {ida_log}"
            except Exception as e:
                self.MessageBox.append(f"[+] 调用 IDA 时发生错误: {e}\n")
            self.MessageBox.append(self.analyze_result)
        except Exception as e:
            self.MessageBox.append(f"[+]分析出错: {e}\n")
    def check_and_run_ai(self):
        if not self.analyze_result or not hasattr(self, 'vuln_c_code'):
            self.MessageBox.append("[+] 请先拖入程序并等待基础分析完成！\n")
            return
            
        self.MessageBox.append("[+] 收到指令，正在唤醒 AI ...\n")
        self.AI_analyze()
    def AI_analyze(self):
        remote_target=self.LineEdit.text().strip()
        user_max_iterations=self.IterationSpinBox.value()
        self.ai_thread=AIThread(self.analyze_result,self.vuln_c_code,self.target_file_path,remote_target,max_iterations=user_max_iterations)
        self.ai_thread.result_signal.connect(self.MessageHistory)
        self.ai_thread.log_signal.connect(self.MessageHistory)
        self.ai_thread.start()
    def Messagefuc(self):
        text=self.Entertext.toPlainText().strip()    
        if text != '\n' and text != '':
            self.Entertext.clear()
            user_html = f"""
            <div style='text-align: left; margin-bottom: 20px;'>
                <b style='color: #007aff;'>我:</b><br>
                <span style='background-color: #e5e5ea; padding: 5px; border-radius: 5px;'>{text}</span>
            </div>
            """
            self.MessageBox.append(user_html)
            self.MessageBox.append("<div style='color: gray; font-size: 12px;'>[AI思考中]....</div>")
            self.content_history.append({"role": "user", "content": text})
            self.message_thread=MessageThread(self.content_history)
            self.message_thread.log_signal.connect(self.MessageBox.append)
            self.message_thread.result_signal.connect(self.MessageHistory)
            self.message_thread.start()
    def MessageHistory(self,response_text):
        ai_html = f"""
        <div style='text-align: left; margin-bottom: 20px;'>
            <b style='color: #28a745;'>DeepSeek:</b><br>
            <div style='white-space: pre-wrap; font-family: Consolas, monospace; color: #333;'>{response_text}</div>
        </div>
        """
        self.MessageBox.append(ai_html)
        self.content_history.append({"role": "assistant", "content": response_text})

if __name__=='__main__':
    app=QApplication([])
    window=Analyzewindow()
    window.show()
    app.exec()