try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class NetworkCnCHTTP(Signature):
    name = "network_cnc_http"
    description = "HTTP traffic contains features indicative of potential command and control activity"
    severity = 2
    confidence = 30
    weight = 0
    categories = ["http", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    def run(self):

        whitelist = [
            "^http://crl\.microsoft\.com/.*",
            "http://.*\.adobe\.com/.*",
            ]

        # HTTP feature checks
        post_noreferer = 0
        nouseragent = 0
        version1 = 0
        low_params = 0
        high_params = 0
        useragent = 0

        # scoring
        cnc_score = 0
        cnc_count = 0

        low_fidelity_params = ["&os=","&win=","&winver=","&winversion=","&win_ver=","win_version=","&windows=","&user=","&username=","&uid=","&gpu=","&ram=","&nat=","&computer=","&compname=","&productid="]
        highrisk_params = ["bot=","botnet=","botid=","bot_id=","&antivirus=","&antiv=","&av="]
        useragents = ["NSIS","WinHttpRequest","WinInet","InetURL"]

        if "network" in self.results and "http" in self.results["network"]:
            for req in self.results["network"]["http"]:
                is_whitelisted = False
                for white in whitelist:
                    if re.match(white, req["uri"], re.IGNORECASE):
                        is_whitelisted = True                              

                # Check HTTP features
                if not is_whitelisted:
                    if req["method"] == "POST" and "Referer:" not in req["data"]:
                        post_noreferer += 1
                        cnc_score += 1
                        if len(req["body"]) < 50 and len(req["body"]) > 0:
                            cnc_score += 1
                        if len(req["path"]) < 15 and len(req["path"]) > 1:
                            cnc_score += 2
                        if "/gate.php" in req["path"]:
                            cnc_score += 3
                        if req["path"].endswith(".php") or req["path"].endswith("="):
                            cnc_score += 1

                    if req["method"] == "POST" and "User-Agent:" not in req["data"]:
                        nouseragent += 1
                        cnc_score += 2

                    if req["method"] == "GET" and "User-Agent:" not in req["data"]:
                        nouseragent += 1
                        cnc_score += 2

                    if req["version"] == "1.0":
                        version1 += 1

                    for low_fidelity_params in low_fidelity_params:
                        low_params += req["path"].count(low_fidelity_params)
                    for low_fidelity_params in low_fidelity_params:
                        low_params += req["body"].count(low_fidelity_params)
                    for highrisk_params in highrisk_params:
                        high_params += req["path"].count(highrisk_params)
                    for highrisk_params in highrisk_params:
                        high_params += req["body"].count(highrisk_params)

                    for useragents in useragents:
                        if useragents in req["user-agent"]:
                            useragent += 1
                            cnc_count += 1

                    if cnc_score > 2:
                        cnc_count += 1

        if post_noreferer > 0:
            self.data.append({"post_no_referer" : "HTTP traffic contains a POST request with no referer header" })
            self.severity = 3
            self.weight += 1

        if nouseragent > 0:
            self.data.append({"no_useragent" : "HTTP traffic contains a request with no user-agent header" })
            self.severity = 3
            self.weight += 1

        if version1 > 0:
            self.data.append({"http_version_old" : "HTTP traffic uses version 1.0" })
            self.weight += 1

        if high_params > 0:
            self.data.append({"malicious_params" : "Detected commonly used malicious parameter names in the HTTP request URI or body" })
            self.severity = 3
            self.weight += 1

        if low_params > 0:
            self.data.append({"suspicious_params" : "Detected suspicious parameters names in the HTTP request URI or body" })
            self.weight += 1

        if useragent > 0:
            self.data.append({"useragent" : "A suspicious user agent was seen in HTTP traffic" })
            self.weight += 1

        if cnc_count > 0:
            self.data.append({"cnc_connections" : "%s requests displayed multiple signs of being CnC related" % (cnc_count)})
            self.severity = 3
            self.weight += 1

        if self.weight:
            return True

        return False
