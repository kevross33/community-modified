from lib.cuckoo.common.abstracts import Signature

class PowershellBypasss(Signature):
    name = "powershell_bypass"
    description = "Attempts to execute a powershell command bypassing execution policy"
    severity = 3
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if "powershell.exe" in cmdline and "-ep bypass" in cmdline:
                return True
        elif call["api"] == "ShellExecuteExW":
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            if "powershell.exe" in filepath and "-ep bypass" in params:
                return True
