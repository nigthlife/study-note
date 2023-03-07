number = input("请输入你的年份：")
number1 = int(number)
if(number1%4 == 0):
    if(number1%100 != 0 ):
        print("这个年份是闰年")
else:
    print("这个年份不是闰年")
