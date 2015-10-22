from lib.cuckoo.common.abstracts import Signature

class ModifiesWindowsFirewall(Signature):
    name = "modifies_windows_firewall"
    description = "Attempts to create a Windows firewall exception"
    severity = 3
    categories = ["network"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if "netsh.exe" in cmdline and "firewall" in cmdline and "action=allow" in cmdline:
                return True
        elif call["api"] == "ShellExecuteExW":
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            if "netsh.exe" in filepath and "firewall" in params and "action=allow" in params:
                return True
