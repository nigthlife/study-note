year = int(input('year:\n'))  #年
month = int(input('month:\n')) #月
day = int(input('day:\n'))      #日

#从一月开始，每个月的日子是第几天
months = (0,31,59,90,120,151,181,212,243,273,304,334)
    #判读输入月份是否在1~12内
if 0 < month <=12:
    
    sum = months[month - 1]
    sum
else:
    #不是就输出错误
    print ('输入的月份错误')
sum += day
leap = 0
if (year %400 == 0) or ((year % 4 == 0) and (year % 100 != 0)):
    leap = 1
if (leap == 1) and (month > 2):
    sum += 1
print("这是:",year,"年的第%d天"%sum,end = ' ')
#print ("的第%d天"%sum)
