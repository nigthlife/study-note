number = [None]*5 #定义一个长度为5的空数组
for x in range(len(number)):
    number[x] = input("请输入：")  #从键盘输入给number数组赋值
number2 = [10,9,8,7,6,5,4,3,2,1]    #定义int类型数组并赋初值

#从小到大排序
def paixu(num):
    for i in range(len(num)-1):
        for j in range(len(num)-i-1):
            if num[j] > num[j+1]:
                num[j],num[j+1]=num[j+1],num[j]
paixu(number2)
print("排序后结果为：",number2)
