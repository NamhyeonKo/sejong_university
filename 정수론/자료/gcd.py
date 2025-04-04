def gcd(a,b):
    if a < b:
        a,b = b,a
    while True:
        q = a // b
        r = a % b
        #print("%d = %d * %d + %d"%(a,b,q,r))
        a = b
        b = r
        if b==0:
            break
    return a

def extended_gcd(a,b):
    if a < b:
        a,b = b,a
    r1 = a
    r2 = b
    s1 = 1
    s2 = 0
    t1 = 0
    t2 = 1
    
    while(r2 > 0): 
        q = r1 // r2
        r = r1 - q * r2
        r1 , r2 = r2 , r
        
        s = s1 - q * s2
        s1 , s2 = s2 , s
        
        t = t1 - q * t2
        t1 , t2 = t2 , t
    print("%d = %d * %d + %d * %d"%(r1,a,s1,b,t1))
    print("s:",s1,"t:",t1)


print(gcd(45,75))
print(gcd(666, 1414))
print(gcd(102, 222))
print(gcd(2**101+16, 2**202+8))

extended_gcd(45, 75)
extended_gcd(666, 1414)
extended_gcd(102, 222)
extended_gcd(2**101+16, 2**202+8)
