numbrt = [None]*10
num = [1,5,8,45,64,123,84,564,456,56,2,222]
for x in range(len(numbrt)):
    numbrt[x]=input("请输入：")
print(num)
def paixu(numbrt):
    for j in range(10-1):
        for i in range(10-j-1):
            if numbrt[i] > numbrt[i+1]:
                numbrt[i],numbrt[i+1]=numbrt[i+1],numbrt[i]
paixu(num)
paixu(numbrt)
'''for i in range(10):
    if num[i] > num[i+1]:
        num[i],num[i+1]=num[i+1],num[i]
        print("第",i)
        print(num)
'''        

print("最后为：",numbrt)             
print("最后为：",num)
