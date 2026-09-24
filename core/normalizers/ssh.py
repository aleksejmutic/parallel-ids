def normalize(result):
    return {
        "success": result.returncode == 0,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "exit_code": result.returncode,
    }