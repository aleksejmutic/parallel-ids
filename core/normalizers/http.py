def normalize(result):
    return {
        "success": result.status_code == 200,
        "raw_stdout": result.text,
        "raw_stderr": None,
        "exit_code": result.status_code,
    }