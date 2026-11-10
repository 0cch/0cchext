a = dbgmem.new(evalmasm("@esp") , 0x20)
print(string.format("addr =%x", a:offset()))
print("size =",a:size())
print("cached size =", a:cachedsize())
print("before swap, a[0]=",a[0],",a1=",a[1])
t = a[1]
a[1] = a[0]
a[0] = t
print("after swap, a[0]=",a[0],",a1=",a[1])
print("to hex string=", a:tohexstring())
print("from hex string=",a:fromhexstring("FFEE"))
c = "abc\123\0cba"
a:setstring(c)
print("set string =", a:getstring())
