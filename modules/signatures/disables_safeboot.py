from lib.cuckoo.common.abstracts import Signature

class DisablesSafeBoot(Signature):
    name = "disables_safe_boot"
    description = "Attempts to disable Safe Boot/Mode"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        keys = [
            ".*\\\\SYSTEM\\\\(Wow6432Node\\\\)?CurrentControlSet\\\\Control\\\\SafeBoot\\\\.*",
            ".*\\\\SYSTEM\\\\(Wow6432Node\\\\)?ControlSet001\\\\Control\\\\SafeBoot\\\\.*",
            ".*\\\\SYSTEM\\\\(Wow6432Node\\\\)?ControlSet002\\\\Control\\\\SafeBoot\\\\.*"
        ]
        for check in keys:
            if self.check_write_key(pattern=check, regex=True):
                return True

        return False
