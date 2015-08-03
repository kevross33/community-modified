try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Java_JS(Signature):
    name = "java_js"
    description = "Executes obfuscated JavaScript containing a Java appplet indicative of an exploit attempt"
    weight = 3
    severity = 3
    categories = ["exploit_kit", "java"]
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
            if re.match(".*\<applet.*code[ ]*=.*archive[ ]*=.*\<\/applet\>.*", buf, re.IGNORECASE):
                return True
        else:
            buf = self.get_argument(call, "Script")
            if re.match(".*\<applet.*code[ ]*=.*archive[ ]*=.*\<\/applet\>.*", buf, re.IGNORECASE):
                return True
