import subprocess
def run_cmd(command, cwd = None):
    try:
        result=subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                cwd= cwd
                )
        output = result.stdout.strip() + '\n' + result.stderr.strip()
        if result.returncode == 0:
            return output.strip()
        else:
            return f"异常推出 {result.returncode}:\n{output.strip()}"
    except subprocess.TimeoutExpired:
        return "Time outed"
    except Exception as e:
        return f'error as {e}'
if __name__ == "__main__":
    try_command = "whoami"
    output = run_cmd(try_command)
    print(output)
