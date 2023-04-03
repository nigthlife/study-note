# [BJDCTF2020]EzPHP

## 0、知识点

>   `$_SERVER` 函数中`QUERY_STRING`

-   `$_SERVER['QUERY_STRING']`不会进行**urldecode**，`$_GET[]`会，可以用url编码绕过

>    `preg_match`绕过

-   使用换行符`%0a`绕过

>   `$_REQUEST`绕过

-   `$_REQUEST`在同时接收`GET`和`POST`参数时，`POST`优先级更高

>   `file_get_contents`绕过

-   使用data协议

>   `sha1`比较

-   `sha1()`函数无法处理数组，`$shana`和$`passwd`都是数组时都是false。

>   `create_function()`代码注入



## 1、关于create_function

**适用范围**：`PHP 4> = 4.0.1`，`PHP 5`，`PHP 7`

>   功能：根据传递的参数**创建匿名函数**，并为其返回唯一名称。

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













