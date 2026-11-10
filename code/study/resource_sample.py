from datetime import datetime, timezone
import platform, subprocess
from pathlib import Path

def resource_sample():
    result = {"at": datetime.now(timezone.utc).isoformat(), "platform": platform.system()}
    commands = {"postgres_processes": ["ps", "-Ao", "pid,ppid,comm,rss"]}
    if platform.system() == "Darwin":
        commands.update(vm_stat=["vm_stat"], memory_pressure=["memory_pressure"], swap=["sysctl", "vm.swapusage"])
    elif platform.system() == "Linux":
        for name in ("meminfo", "vmstat"):
            path = Path("/proc") / name
            if path.exists(): result[name] = path.read_text()
    for name, command in commands.items():
        try:
            p = subprocess.run(command, text=True, capture_output=True, timeout=15)
            output = p.stdout
            if name == "postgres_processes": output = "\n".join(line for line in output.splitlines() if "postgres" in line)
            result[name] = {"exit_code": p.returncode, "stdout": output, "stderr": p.stderr}
        except (OSError, subprocess.SubprocessError) as exc: result[name] = {"error": str(exc)}
    return result
