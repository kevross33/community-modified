from lib.cuckoo.common.abstracts import Signature

class DisablesSystemTools(Signature):
    name = "disables_system_tools"
    description = "Attempts to disable the usage of system tools"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        keys = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\\\System\\\\DisableCMD$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\DisallowRun$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\DisableTaskMgr$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\DisableRegistryTools$"
        ]
        for check in keys:
            if self.check_write_key(pattern=check, regex=True):
                return True

        return False
