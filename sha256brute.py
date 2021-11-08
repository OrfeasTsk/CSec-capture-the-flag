import hashlib
import os
import time

for k in reversed(range(2000,2022)):
    z = str(k)
    for i in range(1,13):
        if(i in range(1,10)):
            x = "0" + str(i) # 0 added before 1 digit numbers
        else:
            x = str(i)
        for j in range(1,32):
            if(j in range(1,10)):
                y = "0" + str(j) # 0 added before 1 digit numbers
            else:
                y = str(j)
            s = z + "-" + x +"-" + y
            s += " " + "bigtent" # Secret added
            m = hashlib.sha256()
            m.update(s.encode())
            f = open("secret.key", "w")
            f.write(m.hexdigest())
            f.close()
            os.system("cat secret.key | gpg --batch --yes --passphrase-fd 0 firefox.log.gz.gpg")
            time.sleep(1)
            print("\n")