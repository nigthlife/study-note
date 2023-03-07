temp = input("请输入一个整数：")
number = int(temp)
#第一层while循环控制总共需要打印多少行的次数
#第二层while循环控制输出空格的个数，第一次输出number然后下一次循环就输出number
#减一个，第三层while循环控制输出*号个数。在每一次输出后减一【
while number:
    i = number - 1
    while i:
        print(' ',end = " ")
        i = i - 1
    j  = number
    while j:
        print('*',end = " ")
        j = j - 1
    print()
    number = number - 1
