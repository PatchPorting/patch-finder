import re

def match_all(string, patterns):
    if all(re.search(x, string) for x in patterns):
        return True
    return False

def match_any(string, patterns):
    if any(re.search(x, string) for x in patterns):
        return True
    return False
