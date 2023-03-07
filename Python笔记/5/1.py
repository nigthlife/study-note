import random
times = 3
#定义一个随机数，从1到10之间随机
secret = random.randint(1,10)

print('--------------欢迎--------------')

#这里给guess赋值，赋一个绝不等于secret的值
guess = 0
#print()，默认是打印完字符串会自动添加一个换行符，end=“”
#参数告诉print()用空格代替换行
print('不妨猜一下小甲鱼现在心里想的是哪个数字',end=" ")
while (guess != secret) and (times > 0) :
    temp = input()
    guess = int(temp)
    times = times - 1
    if guess == secret:
        print('握草，你是小甲鱼心里的蛔虫吗！')
        print('哼，猜中了也没有奖励！')
    else :
        if guess >secret:
            print('大哥，大了大了~~~~！')
        else:
            print('大哥，小了小了~~~~！')
        if times > 0:
            print("再试一次吧：",end = " ")
            print("还剩")
            print(times,"次机会")
        else:
            print("机会用光了")
print('游戏结束，不玩了~~~')
