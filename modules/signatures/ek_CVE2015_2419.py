try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class EK_CVE2015_2419_JS(Signature):
    name = "ek_CVE2015_2419_js"
    description = "Executes obfuscated JavaScript containing Internet Explorer CVE-2015-2419 memory corruption exploit attempt"
    weight = 3
    severity = 3
    categories = ["exploit_kit", "internet explorer", "exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        if re.match(".*\'prototype\'.*\'xexec\'.*\'createElement\'.*\'getElementsByTagName\'.*\'parentNode\'.*\'insertBefore\'.*", buf, re.IGNORECASE):
            return True
