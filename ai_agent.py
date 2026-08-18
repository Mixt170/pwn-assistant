import os
import re
import json
import shutil
import tempfile
import resource
import signal
import subprocess
from tools import run_cmd
from openai import OpenAI
from typing import Optional
from BaseKnowledge import Knowleadge
from PySide6.QtCore import QThread, Signal
kb=Knowleadge(knowledge_path='./tiku')
def search_knowledge(query_keyword: str) -> str:
    #print(f"\n[+] AI 本地数据库查询: {query_keyword}")
    return kb.find_knowledge(query_keyword,k=2)
def build_exp(original_code : str, target_path : str,work_dir : str) -> str:
    
    if not any(k in original_code for k in ['process(', 'remote(', 'interactive()']):
        return original_code
    proxy=f'''
import os,sys,json,atexit
from pwn import*
_STATE_FILE = {repr(os.path.join(work_dir, "state.json"))}
_TARGET_PATH = {repr(target_path)}
class _IOProxy:
    SHELL_SIGNS = [b'uid=', b'gid=', b'euid=', b'flag{{', b'PWNED', b'/bin/sh', b'/bin/bash', b'$ ', b'# ']
    def __init__(self, real_io, mode):
        self._io = real_io
        self._mode = mode          
        self._sent = bytearray()
        self._recv = bytearray()
        self._shell = False
        self._done = False
        self._verified = False
    def _check_shell(self,data:bytes):
        if self._shell:
            return
        for sig in self.SHELL_SIGNS:
            if sig in data:
                self._shell = True
                break
    def _save(self):
        exit_code = None
        try:
            exit_code = self._io.poll()
        except Exception:
            pass
        try:
            with open(_STATE_FILE, 'w') as f:
                json.dump({{
                    "shell": self._shell,
                    "verified": self._verified,
                    "sent": len(self._sent),
                    "sent_hex": self._sent[:800].hex(),
                    "recv": len(self._recv),
                    "preview": self._recv[-1500:].decode('utf-8','replace'),
                    "exit_code": exit_code
                }}, f)
        except Exception:
            pass
    def send(self, data):
        d = data if isinstance(data, bytes) else str(data).encode()
        self._sent.extend(d)
        return self._io.send(d)
    def sendline(self,data):
        d = data if isinstance(data, bytes) else str(data).encode()
        self._sent.extend(d + bytes([10]))
        return self._io.sendline(d)
    def sendafter(self,delim,data):
        self.recvuntil(delim)
        self.send(data)
    def sendlineafter(self,delim,data):
        self.recvuntil(delim)
        self.sendline(data)
    def recv(self, n=4096, timeout=None):
        d = self._io.recv(n, timeout=timeout)
        self._recv.extend(d); self._check_shell(d)
        return d
    def recvline(self,timeout=None):
        d = self._io.recvline(timeout=timeout)
        self._recv.extend(d); self._check_shell(d)
        return d
    def recvuntil(self,delim,drop = False,timeout = None):
        d = self._io.recvuntil(delim, drop=drop, timeout=timeout)
        self._recv.extend(d); self._check_shell(d)
        return d
    def recvall(self,timeout = None):
        d = self._io.recvall(timeout = timeout)
        self._recv.extend(d); self._check_shell(d)
        return d
    def interactive(self):
        try:
            self._io.flush()
        except Exception:
            pass
        try:
            self._io.shutdown('send')
        except Exception:
            pass
        import time
        time.sleep(0.3)
        try:
            data = self._io.recvall(timeout=3)
            self._recv.extend(data)
            self._check_shell(data)
        except Exception:
            pass
        if self._shell and self._mode == 'process':
            try:
                self._io.sendline(b'echo SHELL_OK')
                resp = self._io.recv(timeout=1)
                if b'SHELL_OK' in resp:
                    self._verified = True
            except Exception:
                pass
        time.sleep(0.2)
        self._save()
        try:
            if self._io.poll() is None:
                self._io.kill()
        except Exception:
            pass
        self.close()
    def close(self):
        if not self._done:
            self._done = True
            self._save()
            self._io.close()
    def __enter__(self): 
        return self
    def __exit__(self, *a): 
        self.close()
    def __getattr__(self, name):
        return getattr(self._io, name)
import pwn
_orig_process = pwn.process
_orig_remote = pwn.remote
def _proxy_process(*a, **kw):
    return _IOProxy(_orig_process(*a, **kw), 'process')
def _proxy_remote(*a, **kw):
    return _IOProxy(_orig_remote(*a, **kw), 'remote')
pwn.process = _proxy_process
pwn.remote = _proxy_remote
import sys
sys.modules[__name__].process = _proxy_process
sys.modules[__name__].remote = _proxy_remote
def _emergency_save():
    import gc
    try:
        for obj in gc.get_objects():
            if isinstance(obj, _IOProxy):
                obj._save()
    except Exception:
        pass
atexit.register(_emergency_save)
'''
    return proxy + original_code
def exp_isolated(exp_path: str, target_path: str, work_dir: str, timeout: int) -> dict:
    env=os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    def _limit_resources():
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        os.setpgrp()  
    try:
        proc = subprocess.run(
            ["bash","-c",f"ulimit -c unlimited;cd {work_dir} &&python3 '{exp_path}'"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=work_dir,
            env=env,
            preexec_fn=_limit_resources
            )
        return {
            'rc': proc.returncode,
            'out': proc.stdout,
            'err': proc.stderr,
            'timeout': False,
            'killed': False
        }
    except subprocess.TimeoutExpired as e:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
        return {
            'rc': -9,
            'out': e.stdout.decode('utf-8', 'replace') if e.stdout else '',
            'err': e.stderr.decode('utf-8', 'replace') if e.stderr else '',
            'timeout': True,
            'killed': True
            }
    except Exception as e:
        return {
            'rc': -1, 
            'out': '', 
            'err': str(e), 
            'timeout': False, 
            'killed': False
            }
def analyze_exp(result: dict,work_dir: str, target_path: str) -> str:
    combined = result['out'] + '\n' + result['err']
    state = {}
    state_file = os.path.join(work_dir, "state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = json.load(f)
        except:
            pass
    shell_found = state.get('shell', False)
    success = shell_found or any(s in combined for s in ['uid=', 'gid=', 'flag{', 'PWNED', 'SHELL_OK'])
    crash_keywords = ['Segmentation fault', 'SIGSEGV', 'SIGABRT', 'SIGILL', 'Illegal instruction', 'core dumped']
    child_exit = state.get('exit_code')
    crashed = (result['rc'] in [-11, 139] or any(k in combined for k in crash_keywords) or (child_exit is not None and child_exit < 0 ))
    lines = []
    if success:
        lines.append("EXP成功!检测到shell/flag")
    elif result['timeout']:
        lines.append("脚本超时，可能阻塞或陷入死循环")
    elif crashed:
        lines.append("目标程序发生崩溃")
        if child_exit is not None:
            lines.append(f"exit_code={child_exit}" + (" (SIGSEGV)" if child_exit == -11 else ""))
    else:
        lines.append("脚本执行完成，未检测到成功特征")
    lines.append(f"返回码: {result['rc']} | 发送: {state.get('sent', 0)} bytes | 接收: {state.get('recv', 0)} bytes")
    if crashed:
        gdb_info = analyze_dump(target_path, work_dir)
        if gdb_info:
            lines.append(f"\nGDB 崩溃分析:\n{gdb_info}")
        sent_payload = state.get('sent_hex', '')
        if sent_payload:
            payload_short = sent_payload[:400]
            lines.append(f"\n建议下一步调用 run_gdb 动态调试:")
            lines.append(f'   commands="b main\\nr\\ni r"')
            lines.append(f'   preset="crash"')
            lines.append(f'   payload="{payload_short}"')
            lines.append(f'   payload_is_hex=true')
            lines.append("   （如 payload 不完整，可先用此片段复现崩溃）")
    preview = combined[-2000:] if len(combined) > 2000 else combined
    if preview.strip():
        lines.append(f"\n脚本输出:\n{preview}")

    if state.get('preview'):
        lines.append(f"\n接收数据预览:\n{state['preview'][-1000:]}")
    return '\n'.join(lines)
def analyze_dump(binary_path: str, work_dir: str)-> str:
    cores=[]
    for d in [work_dir, '/tmp', '.']:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.startswith('core') or f.startswith('Core'):
                cores.append(os.path.join(d, f))
    if not cores:
        return ("未找到 core dump 文件\n"
                "提示：尝试以 root 执行 `echo core > /proc/sys/kernel/core_pattern` 启用 core dump")
    core = cores[0]
    gdb_script = os.path.join(work_dir, "gdb_cmds.txt")
    with open(gdb_script, 'w') as f:
        f.write(
"""set confirm off
set pagination off
echo === REGISTERS ===\n
info registers
echo === CODE AT PC ===\n
x/5i $pc
echo === STACK (RSP) ===\n
x/10xg $rsp
echo === BACKTRACE ===\n
bt full
echo === MEMORY MAP ===\n
info proc mappings
quit
""")
    try:
        r = subprocess.run(
            f'gdb -q -batch -x "{gdb_script}" "{binary_path}" "{core}"',
            shell=True, capture_output=True, text=True, timeout=10
        )
        ansi = re.compile(r'\x1B(?:[@-Z\-_]|\[[0-?][ -/]*[@-~])')
        clean = ansi.sub('', r.stdout)
        return clean[:3000] if clean.strip() else "GDB 分析无输出"
    except Exception as e:
        return f"GDB 分析失败: {e}"
def execute_exp(exp_code: str, target_dir: str, target_path: str = None)-> str:
    if not target_path or not os.path.exists(target_path):
        return "目标程序路径无效，无法执行 EXP"
    work_dir = tempfile.mkdtemp(prefix="pwn_exp_")
    try:
        exp_path=os.path.join(work_dir,"exp.py")
        monitored_code = build_exp(exp_code, target_path, work_dir)
        with open(exp_path, 'w', encoding='utf-8') as f:
            f.write(monitored_code)
        result = exp_isolated(exp_path, target_path, work_dir, timeout=15)
        return analyze_exp(result, work_dir, target_path)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
def run_gdb(binary_path: str, commands: str, target_dir: str, payload: Optional[str] = None, payload_is_hex: bool = False, preset: Optional[str] = None, auto_analyze: bool = True ) -> str:
    if not binary_path or not os.path.exists(binary_path):
        return "程序装载异常"
    work_dir = target_dir or os.path.dirname(binary_path) or '.'
    payload_file = None
    script_path = None
    try:
        if preset:
            commands = apply_preset(preset,commands)
        if payload:
            payload_bytes = bytes.fromhex(payload) if payload_is_hex else payload.encode('utf-8')
            payload_file = os.path.join(work_dir, "gdb_payload.bin")
            with open(payload_file, 'wb') as f:
                f.write(payload_bytes)
            commands = inject_payload(commands,payload_file)
        gdb_script = build_gdb_script(commands, payload_file is not None)
        script_path = os.path.join(work_dir,"gdb_script.gdb")
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(gdb_script)
        result = run_command(binary_path, script_path, work_dir, timeout=15)
        cleaned = clean_output(result)
        if auto_analyze:
            analysis = gdb_output(cleaned, preset, payload)
            return analysis + "\n\n" + "=" * 50 + "\n 原始 GDB 输出\n" + "=" * 50 + "\n" + cleaned
        return cleaned
    except Exception as e:
        return f'gdb Error as {e}'
    finally:
        for f in [payload_file,script_path]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
def apply_preset(preset: str, commands: str) -> str:
    base = "echo === GDB PRESET: {} ===\\n".format(preset.upper())
    templates = {
        "crash": """
{user_cmds}
continue
echo === REGISTERS ===\\n
i r
echo === CODE AT PC ===\\n
x/5i $pc
echo === STACK (RSP) ===\\n
x/16xg $rsp
echo === BACKTRACE ===\\n
bt full
echo === MEMORY MAP ===\\n
info proc mappings
""",
        "stack": """
b main
{user_cmds}
echo === STACK FRAME ===\\n
i f
echo === LOCALS ===\\n
i locals
echo === STACK MEMORY ===\\n
x/32xg $rsp
echo === RETURN ADDR ===\\n
x/1xg $rbp+8
""",
        "heap": """
{user_cmds}
echo === HEAP INFO ===\\n
heap
echo === BINS ===\\n
bins
echo === TOP CHUNK ===\\n
x/4xg &main_arena
echo === FASTBINS ===\\n
fastbins
""",
        "offset": """
{user_cmds}
echo === RSP AT CRASH ===\\n
i r rsp
echo === RSP MEMORY ===\\n
x/2xg $rsp
echo === RIP ===\\n
i r rip
"""
    }
    if preset not in templates:
        return commands
    return base + templates[preset].format(user_cmds=commands)
def inject_payload(commands: str, payload_file: str)-> str:
    lines = commands.split('\n')
    has_redirect = any(re.search(r'\b(run|r|start)\b.*<', line) for line in lines)
    if has_redirect:
        return commands
    new_lines = []
    injected = False
    for line in lines:
        stripped=line.strip()
        if not injected and re.match(r'^(run|r|start)(\s|$)', stripped):
            cmd = stripped if not stripped.startswith('r ') else 'run' + stripped[1:]
            new_lines.append(f'{cmd} < "{payload_file}"')
            injected = True
        else:
            new_lines.append(line)
    if not injected:
        new_lines.append(f'run < "{payload_file}"')
    return '\n'.join(new_lines)
def build_gdb_script(commands: str,has_payload: bool)-> str:
    script = [
        "set confirm off",
        "set pagination off",
        "set height 0",
        "set width 0",
        ]
    if has_payload:
        script.append("set inferior-tty /dev/null")
    script.append(commands)
    script.append("quit")
    return '\n'.join(script)
def run_command(binary_path: str, script_path: str, cwd: str, timeout: int)-> str:
    cmd = f'gdb -q -batch -x "{script_path}" "{binary_path}"'
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=cwd
        )
        output = proc.stdout
        if proc.stderr:
            output+=f'\n[stderr]: {proc.stderr}'
        return output
    except subprocess.TimeoutExpired:
        return "GDB 执行超时（目标程序可能阻塞，建议检查 payload 是否缺少换行符）"
    except Exception as e:
        return f"执行异常: {e}"
def clean_output(out_put: str)-> str:
    ansi = re.compile(r'\x1B(?:[@-Z\-_]|\[[0-?][ -/]*[@-~])')
    clean = ansi.sub('', out_put)
    if len(clean) > 4000:
        clean = clean[:2000] + "...[输出过长，中间已截断]...\n" + clean[-2000:]
    return clean
def gdb_output(out_put: str, preset: Optional[str], payload: Optional[str])-> str:
    analysis = ["GDB 分析"]
    findings = []
    regs = {}
    for reg, pat in [
        ('RIP', r'rip\s+0x([0-9a-fA-F]+)'),
        ('RSP', r'rsp\s+0x([0-9a-fA-F]+)'),
        ('RBP', r'rbp\s+0x([0-9a-fA-F]+)'),
        ('RAX', r'rax\s+0x([0-9a-fA-F]+)'),
        ('EIP', r'eip\s+0x([0-9a-fA-F]+)'),
        ('ESP', r'esp\s+0x([0-9a-fA-F]+)'),
    ]:
        m=re.search(pat, out_put)
        if m:
            regs[reg] = f"0x{m.group(1)}"
    if regs:
        findings.append("关键寄存器: " + " | ".join(f"{k}={v}" for k, v in regs.items()))
    sig = re.search(r'Program received signal (\w+)', out_put)
    if sig:
        findings.append(f"信号: {sig.group(1)}")
    crash_addr = re.search(r'Cannot access memory at address (0x[0-9a-fA-F]+)', out_put)
    if crash_addr:
        findings.append(f"非法内存访问: {crash_addr.group(1)}")
    if '0x4141414141414141' in out_put or '0x6161616161616161' in out_put:
        findings.append("发现栈溢出")
    bt = re.search(r'#0\s+([^\n]+)', out_put)
    if bt:
        findings.append(f"崩溃点: {bt.group(1).strip()}")
    else:
        bt_fallback = re.search(r'#\d+\s+(0x[0-9a-fA-F]+)\s+in\s+\?\?', out_put)
        if bt_fallback:
            findings.append(f"崩溃点: {bt_fallback.group(1)} in ?? ()")
        elif crash_addr:
            findings.append(f"崩溃点: 非法内存访问 {crash_addr.group(1)}")
        elif sig:
            findings.append(f"崩溃点: 信号 {sig.group(1)}")
    if preset == 'offset':
        offset = find_offset(out_put)
        if offset :
            findings.append(f"溢出偏移: {offset} bytes")
        else:
            rsp_mem = re.search(r'0x[0-9a-fA-F]+:\s+(0x[0-9a-fA-F]+)', out_put)
            if rsp_mem:
                findings.append(f"RSP 指向值: {rsp_mem.group(1)}")
    elif preset == "heap":
        if 'top:' in out_put or 'fastbins' in out_put:
            findings.append("成功获取堆信息")
    elif preset == 'stack':
        ret_addr = re.search(r'0x[0-9a-fA-F]+ <([^>]+)>', out_put)
        if ret_addr:
            findings.append(f"返回地址附近函数: {ret_addr.group(1)}")
    if not findings:
        findings.append("未提取到明确的崩溃特征，请查看原始输出")
    return '\n'.join(analysis + findings)
def find_offset(out_put: str)-> Optional[int]:
    try:
        from pwnlib.util.cyclic import cyclic_find
    except ImportError:
        return None
    patterns = re.findall(r'0x[0-9a-fA-F]+:\s+(0x[0-9a-fA-F]+)', out_put)
    for pat in patterns:
        val = int(pat, 16)
        for size in [4, 8]:
            try:
                b = val.to_bytes(size, 'little')
                off = cyclic_find(b,n = size)
                if off != -1:
                    return off
            except:
                continue
    return None
tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "search_knowledge",
            "description": "当你分析出漏洞类型后，可以使用此工具在本地题库中搜索相关的利用技巧和 EXP 模板。注意：此工具最多只能调用 5 次。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query_keyword": {
                        "type": "string",
                        "description": "你想搜索的漏洞关键词或特征（例如: 'uaf', 'tcache poisoning', 'ret2libc', 'off by one'）"
                    }
                },
                "required": ["query_keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_exp",
            "description": "执行你编写的 exp.py 脚本。当你写完 payload 后，必须调用此工具测试是否成功 getshell 或拿到 flag。如果测试失败，请根据返回的报错信息修正你的代码并再次测试。",
            "parameters": {
                "type": "object",
                "properties": {
                    "exp_code": {
                        "type": "string",
                        "description": "你编写的 pwntools python 代码的完整内容"
                    }
                },
                "required": ["exp_code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_gdb",
            "description": 
"""【核心调试工具】在目标程序上执行 GDB 动态调试，获取真实寄存器和内存布局。
            
使用方式（三选一）：
1. 【自动模式】指定 preset 模板,AI 只需提供最少信息：
   - preset='crash'  → 崩溃分析，自动提取 RIP/RSP/Backtrace
   - preset='offset' → 偏移计算，需传入 cyclic pattern 作为 payload
   - preset='stack'  → 栈布局分析
   - preset='heap'   → 堆结构分析

2. 【注入模式】提供 payload 参数,run_gdb 自动完成文件写入和 r < file 重定向
   - payload: 字符串或 hex(hex 需设 payload_is_hex=true)
   - 无需手动写 test.txt!

3. 【传统模式】只传 commands,自行控制 GDB 流程

注意：
- 如需输入数据，**直接传 payload 参数**，不要手动写文件！
- 分析栈溢出偏移时，先用 pwntools 生成 cyclic pattern 作为 payload,再设 preset='offset'
- 程序崩溃后，优先用 preset='crash' 一键提取关键信息"""
,
            "parameters": {
                "type": "object",
                "properties": {
                    "commands": {
                        "type": "string",
                        "description": "GDB 批处理指令序列，多条指令用 \\n 分隔。如: 'b main\\nr\\ni r\\nx/20xg $rsp'"
                    },
                    "payload": {
                        "type": "string",
                        "description": "【推荐】要注入的 payload 数据。普通字符串直接填；二进制数据请用 hex 格式并设 payload_is_hex=true"
                    },
                    "payload_is_hex": {
                        "type": "boolean",
                        "description": "payload 是否为 hex 字符串，默认 false"
                    },
                    "preset": {
                        "type": "string",
                        "enum": ["crash", "stack", "heap", "offset"],
                        "description": "预设调试模板。crash=崩溃分析, offset=自动算偏移, stack=栈调试, heap=堆调试"
                    }
                },
                "required": ["commands"],
            },
        },
    }
]
class AIThread(QThread):
    log_signal = Signal(str)
    result_signal = Signal(str)
    def __init__(self,analyze_result,vuln_c_code,target_path,remote_target,max_iterations=15):
        super().__init__()
        self.analyze_result = analyze_result
        self.vuln_c_code = vuln_c_code
        self.target_path = target_path
        self.remote_target = remote_target
        self.max_iterations = max_iterations
    def run(self):
        self.log_signal.emit("[+]AI分析程序中\n")
        try:
            api_key = os.getenv("API_KEY")
            if not api_key:
                self.log_signal.emit("[+] 未找到API_KEY,请检查 .env 文件！")
                return
            client = OpenAI(
                base_url = 'https://api.deepseek.com/v1',
                api_key = api_key
            )
            system_instruction = f"""
你是一名顶级的安全专家。
【绝对规则】：
1. 语言限制：必须使用【中文】回答！
2. 字数限制：极度精简，控制在 2000 字以内！
3. 格式限制：绝对不要复述/抄写我发给你的 C 伪代码和静态信息！你的 exp.py 代码必须严格包裹在 ```python 和 ``` 之间,绝对不要在exp.py代码块外写多余的代码!
4. 输出要求：一针见血地指出漏洞位置（如 gets 导致栈溢出），给出核心构造思路，然后直接输出最终的 pwntools exp.py 即可。
5. 工具声明:如果你调用了工具,必须在开头第一行醒目地标出:【参考本地题解路径:xxx】。
6. 必须根据我提供的【目标运行环境】来编写连接代码(remote 或 process),必须严格根据【目标运行环境】编写连接代码！如果是本地调试模式，绝对禁止使用 remote()；如果是远程模式，可以使用 process()以便run_gdb调试。违反此规则将导致 EXP 测试失败！
7. 当你调用 `execute_exp` 发现回显中已经拿到 shell(如出现 uid=, gid=）或测试成功时，禁止再次调用任何工具进行重复验证！你必须立刻停止行动，并直接输出最终的 ```python 代码！
8. 遇到无法确定问题的EXP崩溃,你必须调用 `run_gdb` 排查，通过崩溃时的 RIP/EIP 或者 $rsp 内存，排查出问题所在，然后再编写正式的 EXP。
9. 当你调用 `execute_exp` 后,如果exp测试失败,你必须调用 `run_gdb` 排查原因
10.你只能进行{self.max_iterations}交互，最后一次务必调用 `execute_exp` 测试exp.py
"""
            system_instruction += f"""
【GDB 使用规范】
1. 当你需要向程序输入数据来调试时，禁止让 python 先写文件！
   正确做法：直接调用 run_gdb,把 payload 传入 payload 参数。
2. 当你需要计算栈溢出偏移时：
   → 先调用 execute_exp 测试，获取崩溃时的 payload_hex
   → 再调用 run_gdb(preset="offset", payload=..., payload_is_hex=true)
   → 从返回结果中读取 "溢出偏移: XX bytes"
3. 当 execute_exp 报告崩溃时，必须接着调用 run_gdb(preset="crash") 分析 RIP 和 RSP,
   根据 "崩溃点" 和 "关键寄存器" 修正你的 EXP。
4. 禁止在 run_gdb 的 commands 里写 "r < test.txt" 这类手动重定向！
【远程模式工作流】
如果目标运行环境是【远程打靶模式】：
1.远程靶机没有 GDB,你无法在远程运行 run_gdb。
2.但你随时可以调用 run_gdb 调试【本地】二进制文件，用于验证偏移、排查崩溃。
3. 必须策略：先编写 io = process('{self.target_path}') 版本，在本地用 execute_exp + run_gdb 完全调通，确认能稳定拿到 shell 后，再输出最终的 io = remote(...)版本。
4. 如果本地 process 版本都调不通，绝对不要盲打远程，那是浪费交互次数。
"""
            if self.remote_target:
                parts = self.remote_target.split()
                if len(parts) == 2:
                    ip = parts[0]
                    port = parts[1]
                    target_env = f"【远程打靶模式】... io = remote('{ip}', {port})"
            else: 
                target_env = f"【本地调试模式】... io = process('{self.target_path}')"
            content = f"""
你在做一道CTF Pwn 题目。请仔细分析下面的静态情报和 C 伪代码。
分析出漏洞后，可选择调用 `search_knowledge` 工具查询我本地的知识库，最后输出一份完整的 exp.py。

[目标运行环境]
{target_env}

[调试策略]
本地二进制始终可用于调试。如果最终目标是远程，强烈建议先编写 process
('{self.target_path}') 版本在本地验证，调通后再切换为 remote()

run_gdb 随时可调用，用于分析本地二进制。
[任务要求]
1.深入分析并指出代码中存在的安全缺陷（例如：栈溢出、格式化字符串等
2.遇到不确定的思路时，务必调用`search_knowledge` 工具查询我本地的知识库。
3.说明漏洞的切入点并给出解题的脚本编译思路
4.提供用于构建 exp.py 的 Python pwntools 核心代码片段（例如如何构造 ROP 链、计算偏移）
5.如果你调用了工具查阅本地资料，请在最终回答的开头，明确列出你参考的【本地题解来源路径】。
6.必须，务必用中文回答，严禁擅自更改语言
【静态信息】
{self.analyze_result}

【C 伪代码】
{self.vuln_c_code}
"""
            self.log_signal.emit("[+] 正在阅读反编译代码...\n")
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": content}
            ]
            max_loop = self.max_iterations
            count = 0
            final_text = ""
            for i in range(max_loop):
                count +=1
                response = client.chat.completions.create(
                    model='deepseek-v4-pro',
                    messages=messages,
                    tools=tools_schema,
                    temperature=0.3
                    )
                response_message = response.choices[0].message
                if response_message.tool_calls:
                    messages.append(response_message)
                    for tool_call in response_message.tool_calls:
                        tool_name = tool_call.function.name
                        search_args = json.loads(tool_call.function.arguments)
                        tool_result = ''
                        if tool_name == "search_knowledge":
                            keyword = search_args.get("query_keyword", "无")
                            self.log_signal.emit(f"[+] AI 决定查阅本地资料，搜索关键词: '{keyword}' ...\n")
                            tool_result = search_knowledge(keyword)
                        elif tool_name == "execute_exp":
                            exp_code = search_args.get("exp_code", "")
                            self.log_signal.emit(f"[+] AI 正在测试EXP...\n")
                            target_dir = os.path.dirname(self.target_path) if self.target_path else "."
                            tool_result = execute_exp(exp_code, target_dir, self.target_path)
                            if "崩溃" in tool_result:
                                self.log_signal.emit("[+] 测试失败\n")
                                tool_result += "\n\n[系统警告]脚本导致目标崩溃。请立即调用 run_gdb(preset='crash') 分析本地二进制，根据 RIP/RSP 修正后再测试。"
                            elif "EXP成功" in tool_result:
                                self.log_signal.emit("[+] 测试成功\n")
                                tool_result += "\n\nEXP 测试已成功(拿到Shell)请立即输出最终的 python 代码并结束对话！"
                            elif "超时" in tool_result:
                                self.log_signal.emit("[+] 测试超时")
                                tool_result += "\n\n[系统警告]脚本执行超时，请检查是否进入死循环，或改用 recvuntil() 等待特定输出。"
                            else:
                                self.log_signal.emit("[+] 测试未生效\n")
                                tool_result += "\n\n[系统警告]EXP 执行成功但未检测到成功特征,请检查payload构造。"
                        elif tool_name == "run_gdb":
                            commands = search_args.get("commands", "")
                            payload = search_args.get("payload")
                            payload_is_hex = search_args.get("payload_is_hex", False)
                            preset = search_args.get("preset")
                            self.log_signal.emit(f"[+] AI 正在使用 GDB 动态调试...\n")
                            target_dir = os.path.dirname(self.target_path) if self.target_path else "."
                            tool_result = run_gdb(self.target_path, commands, target_dir,payload=payload,payload_is_hex=payload_is_hex,preset=preset)
                            if self.remote_target:
                                tool_result += "\n\n[系统提示] 当前为远程打靶模式，以上 GDB 结果来自[本地二进制]。"\
                                    "请确认本地 process() 版本调通后，再输出最终的 remote() 版本 EXP。"
                            if "Time outed" in tool_result or "超时" in tool_result:
                                tool_result += "\n\n[系统警告]GDB卡死超时。请确保通过 payload 参数传入数据（而非 commands 里写重定向），并检查程序是否在等待特定输入格式。"
                                self.log_signal.emit("[+] GDB 调试超时\n")
                            else:
                                self.log_signal.emit("[+] GDB 调试结束\n")
                        else:
                            self.log_signal.emit(f"[+] 警告:AI 试图调用不存在的工具 '{tool_name}'\n")
                            tool_result = f"\n[系统警告]你调用的工具 '{tool_name}' 不存在！你只能调用系统提供给你的工具（search_knowledge 或 execute_exp 或 run_gdb）。请立刻纠正你的行为！"
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": tool_call.function.name,
                            "content": tool_result if tool_result else "无结果",
                            })
                    self.log_signal.emit("[+]工具调用完毕,AI正在推演下一步逻辑\n")
                    if i == max_loop - 1 and response_message.tool_calls:
                        self.log_signal.emit("[+] 已达到最大尝试次数，强制停止 AI 测试。\n")
                        final_text = f"[+]AI经历了{max_loop}次交互仍未成功拿到Shell"
                        break               
                else:
                    final_text = response_message.content
                    break
            self.log_signal.emit(f"[调试信息] AI 最终响应文本长度: {len(final_text) if final_text else 0}")
            self.log_signal.emit(f"[+]本次共进行{count}次交互")
            if final_text:
                self.result_signal.emit(final_text)
                match = re.search(r'```python(.*?)```', final_text, re.DOTALL)
                if match:
                    exp_code = match.group(1).strip()
                    target_dir = os.path.dirname(self.target_path)
                    exp_path = os.path.join(target_dir, "exp.py")
                    try:
                        with open(exp_path,'w',encoding='utf-8') as f:
                            f.write(exp_code)
                            success_msg = f"""
            <div style='color: #198754; font-weight: bold; margin-bottom: 20px;'>
                [+] 成功提取 EXP,已自动保存至: {exp_path}
            </div>
            """
                            self.log_signal.emit(success_msg)
                    except Exception as e:
                        self.log_signal.emit(f"Error as {e}")
            else:
                self.log_signal.emit("[+] 警告: AI 返回了空文本。")
        except Exception as e:
            self.log_signal.emit(f"Error as {e}")
        