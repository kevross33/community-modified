from lib.cuckoo.common.abstracts import Signature

class ModifiesBootConfig(Signature):
    name = "modifies_boot_config"
    description = "Attempts to modify the Boot Configuration Data file"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if "bcdedit" in cmdline and "/set" in cmdline:
                return True
        elif call["api"] == "ShellExecuteExW":
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            if "bcdedit" in filepath and "/set" in params:
                return True
