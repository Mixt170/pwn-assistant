=======================功能概述=======================
1.支持用户自定义AI工具调用次数上限(1~50)
2.通过劫持IO记录EXP所有收发数据
3.GDB自动化调试且支持四种预设模式(crash/stack/heap/offset)
4.本地知识库基于TF-IDF检索
=======================依赖环境=======================
操作系统：Linux
运行环境：Python: 3.8+
必要外部工具：IDA Pro，GDB
Python依赖：PySide6，openai，python-dotenv，scikit-learn，pwntools
API Key: 需自行申请DeepSeek API Key，并填入.env文件
=======================安装与配置======================
1.解压源码压缩包至本地目录

2.安装Python依赖:
在根目录下执行pip install -r requirements.txt

3.编辑.env文件，并填入实际值：
API_KEY = sk-
IDA_PATH = xxx/IDA/idat

4.启用Core Dump:
ulimit -c unlimited
=======================结构==========================
1.main.py：程序入口
2.gui.py：基础GUI界面
3.analyze.py：静态分析，反编译调度，AI启动
4.ai_agent.py：AI主控线程
5.ai_message.py：普通对话线程       
6.tools.py：通用命令执行工具
7.BaseKnowledge.py：本地知识库检索
8.ida_dump.py：IDA反编译脚本
9.login.py：启动时环境配置提示窗口
=======================使用流程=======================
1.启动程序：
python3 main.py

2.拖入目标二进制：
将vuln文件拖拽至窗口，系统自动执行：
checksec安全机制检查
ldd识别libc路径，提取system，bin_sh，execve，pop_rdi等关键偏移
自动检索ROP gadget
调用IDA反编译，生成vuln_c_code.txt

3.设置循环次数（可选）:
在右侧"循环次数"输入框中调节AI最大尝试次数(默认15,范围1~50)

4.点击"AI分析":
AI启动(deepseek-v4-pro)，开启多轮交互:
可调用search_knowledge检索本地题解
可调用execute_exp执行并测试当前EXP
可调用run_gdb动态调试(支持预设模式: crash/offset/heap/stack)

5.若AI测试成功，最终EXP代码将自动保存为二进制所在目录下的exp.py
若AI达到最大尝试次数仍未成功，返回失败提示
用户也可在底部对话框与AI进行普通对话(deepseek-v4-flash)