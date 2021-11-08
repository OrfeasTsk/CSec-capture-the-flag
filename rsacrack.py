import math

N = 127670779
e = 7
Ex = 122880244
Ey = 27613890


p = math.floor(math.sqrt(N)); # Start from the floor of the square root (Better complexity)

while p > 1:
    if(N % p != 0): # First divisor of N found
        p = p - 1 
    else:
        break;    

q = int(N / p) # Second divosor of N found

print("p = " + str(p) + " q = " + str(q))

phi = (p-1)*(q-1)

d = 0
while (d * e) % phi != 1: # d = e ^ -1 mod phi
    d = d + 1  

print("d = " + str(d))

x = Ex
y = Ey
for i in range(d - 1): # Modular exponentiation in order to avoid overflow
    x = (x * Ex) % N
    y = (y * Ey) % N

print ("x = " + str(x) + " y = " + str(y))

print("x||y = "+ str(x) + str(y))