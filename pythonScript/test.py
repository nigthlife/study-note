num = "c8e9aca0c6f2e5f3e8c4efe7a1a0d4e8e5a0e6ece1e7a0e9f3baa0e8eafae3f9e4eafae2eae4e3eaebfaebe3f5e7e9f3e4e3e8eaf9eaf3e2e4e6f2"
str = ''
for i in range(0,len(num),2):
    a = num[i:i+2] # 每次获取两位十六进制
    result1 = int(a,16) # 将十六进制转换成十进制
    #print(result1)
    asc = chr(result1-128)# 将十进制转换成ASCII编码，将十进制数减128（因为ASCII码值为0-127）
    str=str+asc # 拼接字符
print(str)