from lib.cuckoo.common.abstracts import Signature

class FileSearch(Signature):
    name = "file_search"
    description = "Iterates over a large number of files using a wildcard search"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*\\\\\*\.\*$",
            ".*\\\\\*$"
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True) > 15:
                return True

        return False
