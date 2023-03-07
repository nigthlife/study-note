#def函数也就是方法
def maopao(*su):
    #外层循环
    for i in range(len(su)-1):
       #内层循环
        count = 0
        for j in range(len(su)-1-i):
            if su[j] > su[j +1]:
                su[j],su[j+1] = su[j+1],su[j]
                count +=1
        if 0==count:
            break
                
    return su

maopao(32,12,66,17,80,58,46,25,7)
