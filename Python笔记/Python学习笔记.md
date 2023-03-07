# Python基础学习笔记

## 0、





## 1、变量

#### 1、变量类型

-   **整型**
    -   Python 2.x中有`int`和`long`两种类型的整数
    -   Python 3.x中整数只有int这一种了

-   **浮点型**
-   **字符串型**
-   **布尔型**
-   **复数型**
    -   跟数学上的复数表示一样，唯一不同的是虚部的`i`换成了`j`，这个类型并不常用



#### 2、命名规范

-   **硬性规则**
    -   变量名由字母、数字和下划线构成，数字不能开头
    -   大小写敏感
    -   不要跟关键字和系统保留字冲突
-   **PEP 8要求**
    -   用小写字母拼写，多个单词用下划线连接
    -   受保护的实例属性用单个下划线开头
    -   私有的实例属性用两个下划线开头



#### 3、工具函数

>   ==**Python中可以使用`type`函数对变量的类型进行检查**==

-   **==Python中内置的函数对变量类型进行转换==**
    -   `int()`：将一个数值或字符串转换成整数，可以指定进制
    -   `float()`：将一个字符串转换成浮点数。
    -   `str()`：将指定的对象转换成字符串形式，可以指定编码
    -   `chr()`：将整数转换成该编码对应的字符串（一个字符）
    -   `ord()`：将字符串（一个字符）转换成对应的编码（整数）



```Python
使用 input() 函数获取键盘输入(字符串)
使用 int()   函数将输入的字符串转换成整数
使用 print() 函数输出带占位符的字符串

a = int(input('a = '))
b = int(input('b = '))
print('%d + %d = %d' % (a, b, a + b))
print('%d %% %d = %d' % (a, b, a % b))


# 其中%d是整数的占位符，%f是小数的占位符，
# %%表示百分号，因为百分号代表了占位符，所以带占位符的字符串中要表示百分号必须写成%%
```

#### 4、运算符

| 运算符                                                       | 描述                           |
| ------------------------------------------------------------ | ------------------------------ |
| `[]` `[:]`                                                   | 下标，切片                     |
| `**`                                                         | 指数                           |
| `~` `+` `-`                                                  | 按位取反, 正负号               |
| `*` `/` `%` `//`                                             | 乘，除，模，整除               |
| `+` `-`                                                      | 加，减                         |
| `>>` `<<`                                                    | 右移，左移                     |
| `&`                                                          | 按位与                         |
| `^` `\|`                                                      | 按位异或，按位或               |
| `<=` `<` `>` `>=`                                            | 小于等于，小于，大于，大于等于 |
| `==` `!=`                                                    | 等于，不等于                   |
| `is`  `is not`                                               | 身份运算符                     |
| `in` `not in`                                                | 成员运算符                     |
| `not` `or` `and`                                             | 逻辑运算符                     |
| `=` `+=` `-=` `*=` `/=` `%=` `//=` `**=` `&=` `|=` `^=` `>>=` `<<=` | （复合）赋值运算符             |

```Python
"""
赋值运算符和复合赋值运算符
"""
a = 10
b = 3
a += b        # 相当于：a = a + b
a *= a + 2    # 相当于：a = a * (a + 2)
print(a)      # 算一下这里会输出什么
```

==比较运算符的优先级高于赋值运算符==

```python
# flag0 = 1 == 1先做1 == 1产生布尔值True，再将这个值赋值给变量flag0
flag0 = 1 == 1
```

## 2、分支

### 1、if

>   -   **if**
>   -   **elif**
>   -   **else**
>
>   -   与其他语言的区别：
>
>       -   Python中没有用花括号来构造代码块而是**使用了缩进的方式来表示代码的层次结构**
>       -   **连续的代码如果保持了相同的缩进那么它们属于同一个代码块**、
>       -   **缩进通常使用4个空格，**
>
>   -   **案例**
>
>   -   ```python
>       """
>       分段函数求值
>       
>               3x - 5  (x > 1)
>       f(x) =  x + 2   (-1 <= x <= 1)
>               5x + 3  (x < -1)
>       
>       """
>       
>       x = float(input('x = '))
>       if x > 1:
>           y = 3 * x - 5
>       elif x >= -1:
>           y = x + 2
>       else:
>           y = 5 * x + 3
>       print('f(%.2f) = %.2f' % (x, y)) # 保留两位小数
>       
>       
>       # 使用扁平化的结构
>       x = float(input('x = '))
>       if x > 1:
>           y = 3 * x - 5
>       else:
>           if x >= -1:
>               y = x + 2
>           else:
>               y = 5 * x + 3
>       print('f(%.2f) = %.2f' % (x, y))
>       ```
>
>       ```Python
>       """
>       英制单位英寸与公制单位厘米互换
>       """
>       value = float(input('请输入长度: '))
>       unit = input('请输入单位: ')
>       if unit == 'in' or unit == '英寸':
>           print('%f英寸 = %f厘米' % (value, value * 2.54))
>       elif unit == 'cm' or unit == '厘米':
>           print('%f厘米 = %f英寸' % (value, value / 2.54))
>       else:
>           print('请输入有效的单位')
>       
>       ```
>
>       

### 2、循环

>   -   ==for-in循环==
>
>       -   如果**明确**的**知道**循环**执行的次数**或者要**对一个容器进行迭代**，推荐使用`for-in`循环
>
>       -   ```python
>           """
>           用for循环实现1~100求和
>           """
>           
>           sum = 0
>           for x in range(101):
>               sum += x
>           print(sum)
>           
>           # 代码中的range(1, 101)可以用来构造一个从1到100的范围，
>           # 当我们把这样一个范围放到for-in循环中，就可以通过前面的循环变量x依次取出从1到100的整数
>           ```
>
>       -   **关于range()**
>
>           -   `range(101)`：可以用来**产生0到100范围**的整数，需要注意的是**取不到101**
>           -   `range(1, 101)`：可以用来**产生1到100范围**的整数，相当于前面是闭区间后面是开区间
>           -   `range(1, 101, 2)`：可以用来**产生1到100的奇数**，其中2是步长，每次数值递增的值。
>           -   `range(100, 0, -2)`：可以用来**产生100到1的偶数**，其中-2是步长，每次数字递减的值。
>
>   -   ==while==
>
>       -   不知道具体循环次数的循环结构，我们推荐使用`while`循环
>
>       -   **经典猜数字案例**
>
>           -   ```python
>               """
>               猜数字游戏
>               """
>               import random
>               
>               answer = random.randint(1, 100)
>               counter = 0
>               while True:
>                   counter += 1
>                   number = int(input('请输入: '))
>                   if number < answer:
>                       print('大一点')
>                   elif number > answer:
>                       print('小一点')
>                   else:
>                       print('恭喜你猜对了!')
>                       break
>               print('你总共猜了%d次' % counter)
>               if counter > 7:
>                   print('你的智商余额明显不足')
>               ```
>
>               
>
>   

## 3、函数与模块

### 1、函数

>   -   **定义函数**
>
>       -   使用`def`关键字来定义函数
>
>       -   函数执行完成后我们可以通过`return`关键字来返回一个值
>
>       -   **函数的参数可以有默认值，也支持使用可变参数**
>
>           -   以下两个函数都加了默认值，如果调用的时候没有传入对应的参数值就会使用默认值
>
>           -   ```python
>               from random import randint
>               
>               def roll_dice(n=2):
>                   """摇色子"""
>                   total = 0
>                   for _ in range(n):
>                       total += randint(1, 6)
>                   return total
>               
>               def add(a=0, b=0, c=0):
>                   """三个数相加"""
>                   return a + b + c
>               
>               # 如果没有指定参数那么使用默认值摇两颗色子
>               print(roll_dice())
>               # 摇三颗色子
>               print(roll_dice(3))
>               print(add())
>               print(add(1))
>               print(add(1, 2))
>               print(add(1, 2, 3))
>               # 传递参数时可以不按照设定的顺序进行传递
>               print(add(c=50, a=100, b=200))
>               ```
>
>       -   **可变参数**
>
>           -   ```python
>               # 在参数名前面的*表示args是一个可变参数
>               def add(*args):
>                   total = 0
>                   for val in args:
>                       total += val
>                   return total
>               
>               
>               # 在调用add函数时可以传入0个或多个参数
>               print(add())
>               print(add(1))
>               print(add(1, 2))
>               print(add(1, 2, 3))
>               print(add(1, 3, 5, 7, 9))
>               ```

>   -   **模块管理函数**
>
>       -   当出现如下代码
>
>       -   ```python
>           def foo():
>               print('hello, world!')
>           
>           
>           def foo():
>               print('goodbye, world!')
>           
>           
>           # 下面的代码会输出什么呢？
>           foo()
>           # 答案是会输出：goodbye, world!
>           # 因为后面的foo覆盖了之前导入的foo
>           ```
>
>       -   ```python
>           # 将两个函数写在不同的文件中，在通过import导入，依此来分清辨别
>           import module1 as m1
>           import module2 as m2
>           
>           m1.foo()
>           m2.foo()
>           ```
>
>   -   >    如果我们导入的模块除了定义函数之外还有可以执行代码，那么Python解释器在导入这个模块时就会执行这些代码
>       >
>       >    事实上我们可能并不希望如此，因此如果我们在模块中编写了执行代码，最好是将这些执行代码放入如下所示的条件中，
>       >
>       >    这样的话除非直接运行该模块，否则if条件下的这些代码是不会执行的，因为只有直接执行的模块的名字才是`__main__`
>
>       -   ```py
>           def foo():
>               pass
>           
>           def bar():
>               pass
>           
>           # __name__是Python中一个隐含的变量它代表了模块的名字
>           # 只有被Python解释器直接执行的模块的名字才是__main__才会执行if中的代码
>           if __name__ == '__main__':
>               print('call foo()')
>               foo()
>               print('call bar()')
>               bar()
>           ----------------------------------------------------------------    
>               
>           # 另一个文件中导入这个模块
>           import module3
>           
>           # 导入module3时 不会执行模块中if条件成立时的代码 因为模块的名字是module3而不是__main__
>           ```
>
>           

## 4、字符串、常用数据结构

>   -   **字符串基础案例**
>
>       -   ```PY
>           s1 = 'hello, world!'
>           s2 = "hello, world!"
>           # 以三个双引号或单引号开头的字符串可以折行
>           s3 = """
>           hello, 
>           world!
>           """
>           print(s1, s2, s3, end='')
>           
>           ---------------------------------------------------------------
>           # \141和\x61都代表小写字母a,前者是八进制的表示法，后者是十六进制的表示法
>           # 也可以使用Unicode字符编码来表示字符，\u9a86\u660a
>           s1 = '\141\142\143\x61\x62\x63'
>           s2 = '\u9a86\u660a'
>           print(s1, s2)
>           
>           ---------------------------------------------------------------
>           # 如果不希望字符串中的[\]表示转义，
>           # 可以通过在字符串的最前面加上字母r来加以说明
>           s1 = r'\'hello, world!\''
>           s2 = r'\n\\hello, world!\\\n'
>           print(s1, s2, end='')
>           ```

>   **字符串的运算**
>
>   -   使用`+`运算符来实现**字符串的拼接**
>   -   使用`*`运算符来**重复一个字符串的内容**
>   -   使用`in`和`not in`来判断一个字符串是否包含另外一个字符串
>   -   可以用`[]`和`[:]`运算符从字符串取出某个字符或某些字符（切片运算）
>
>   ```py
>   s1 = 'hello ' * 3
>   print(s1) # hello hello hello 
>   
>   s2 = 'world'
>   s1 += s2
>   print(s1) # hello hello hello world
>   print('ll' in s1) # True
>   print('good' in s1) # False
>   
>   str2 = 'abc123456'
>   # 从字符串中取出指定位置的字符(下标运算)
>   print(str2[2]) # c
>   
>   # 字符串切片(从指定的开始索引到指定的结束索引)
>   print(str2[2:5]) # c12			从2开始5结束，步长为1
>   print(str2[2:]) # c123456		从2开始的一直到末尾，步长为1
>   print(str2[2::2]) # c246		从2开始一直到末尾，步长为2
>   print(str2[::2]) # ac246		从首位开始到末尾，步长为2
>   print(str2[::-1]) # 654321cba	从末尾开始，一直到首位，步长为1
>   print(str2[-3:-1]) # 45			从倒数第3开始，到倒数第1个结束
>   ```
>
>   

>   ==**字符串处理**==
>
>   ```py
>   str1 = 'hello, world!'
>   # 通过内置函数len计算字符串的长度
>   print(len(str1)) # 13
>   # 获得字符串首字母大写的拷贝
>   print(str1.capitalize()) # Hello, world!
>   # 获得字符串每个单词首字母大写的拷贝
>   print(str1.title()) # Hello, World!
>   # 获得字符串变大写后的拷贝
>   print(str1.upper()) # HELLO, WORLD!
>   # 从字符串中查找子串所在位置
>   print(str1.find('or')) # 8
>   print(str1.find('shit')) # -1
>   # 与find类似但找不到子串时会引发异常
>   # print(str1.index('or'))
>   # print(str1.index('shit'))
>   # 检查字符串是否以指定的字符串开头
>   print(str1.startswith('He')) # False
>   print(str1.startswith('hel')) # True
>   # 检查字符串是否以指定的字符串结尾
>   print(str1.endswith('!')) # True
>   # 将字符串以指定的宽度居中并在两侧填充指定的字符
>   print(str1.center(50, '*'))
>   # 将字符串以指定的宽度靠右放置左侧填充指定的字符
>   print(str1.rjust(50, ' '))
>   str2 = 'abc123456'
>   # 检查字符串是否由数字构成
>   print(str2.isdigit())  # False
>   # 检查字符串是否以字母构成
>   print(str2.isalpha())  # False
>   # 检查字符串是否以数字和字母构成
>   print(str2.isalnum())  # True
>   str3 = '  jackfrued@126.com '
>   print(str3)
>   # 获得字符串修剪左右两侧空格之后的拷贝
>   print(str3.strip())
>   ```
>
>   

>   **格式化输出字符串**
>
>   ```py
>   # 一般方式
>   a, b = 5, 10
>   print('%d * %d = %d' % (a, b, a * b))
>   
>   # 字符串提供的方法
>   a, b = 5, 10
>   print('{0} * {1} = {2}'.format(a, b, a * b))
>   
>   # Python 3.6以后，格式化字符串还有更为简洁的书写方式，就是在字符串前加上字母f
>   a, b = 5, 10
>   print(f'{a} * {b} = {a * b}')
>   ```
>
>   



### 1、列表

>   是一种**结构化的**、**非标量类型**，它是**值的有序**序列，
>
>   每个值都可以通过索引进行标识，
>
>   定义列表可以将列表的元素放在`[]`中，多个元素用`,`进行分隔，
>
>   可以使用`for`循环对列表元素进行遍历，也可以使用`[]`或`[:]`运算符取出列表中的一个或多个元素。

>   ==如何定义列表、如何遍历列表以及列表的下标运算==
>
>   ```py
>   list1 = [1, 3, 5, 7, 100]
>   print(list1) # [1, 3, 5, 7, 100]
>   
>   # 乘号表示列表元素的重复
>   list2 = ['hello'] * 3
>   print(list2) # ['hello', 'hello', 'hello']
>   
>   # 计算列表长度(元素个数)
>   print(len(list1)) # 5
>   
>   # 下标(索引)运算
>   print(list1[0]) # 1
>   print(list1[4]) # 100
>   # print(list1[5])  # IndexError: list index out of range
>   print(list1[-1]) # 100
>   print(list1[-3]) # 5
>   
>   
>   list1[2] = 300
>   print(list1) # [1, 3, 300, 7, 100]
>   
>   # 通过循环用下标遍历列表元素
>   for index in range(len(list1)):
>       print(list1[index])
>       
>   # 通过for循环遍历列表元素
>   for elem in list1:
>       print(elem)
>       
>   # 通过enumerate函数处理列表之后再遍历可以同时获得元素索引和值
>   for index, elem in enumerate(list1):
>       print(index, elem)
>   ```
>
>   ==如何向列表中添加元素以及如何从列表中移除元素==
>
>   ```py
>   list1 = [1, 3, 5, 7, 100]
>   
>   # 添加元素
>   list1.append(200)
>   list1.insert(1, 400)
>   
>   # 合并两个列表
>   # list1.extend([1000, 2000])
>   list1 += [1000, 2000]
>   print(list1) # [1, 400, 3, 5, 7, 100, 200, 1000, 2000]
>   print(len(list1)) # 9
>   
>   # 先通过成员运算判断元素是否在列表中，如果存在就删除该元素
>   if 3 in list1:
>   	list1.remove(3)
>   if 1234 in list1:
>       list1.remove(1234)
>   print(list1) # [1, 400, 5, 7, 100, 200, 1000, 2000]
>   
>   # 从指定的位置删除元素
>   list1.pop(0)
>   list1.pop(len(list1) - 1)
>   print(list1) # [400, 5, 7, 100, 200, 1000]
>   
>   # 清空列表元素
>   list1.clear()
>   print(list1) # []
>   ```
>
>   ==列表也可以做切片操作，通过切片操作我们可以实现对列表的复制或者将列表中的一部分取出来创建出新的列表==
>
>   ```py
>   fruits = ['grape', 'apple', 'strawberry', 'waxberry']
>   fruits += ['pitaya', 'pear', 'mango']
>   
>   # 列表切片
>   fruits2 = fruits[1:4]
>   print(fruits2) # apple strawberry waxberry
>   
>   # 可以通过完整切片操作来复制列表
>   fruits3 = fruits[:]
>   print(fruits3) # ['grape', 'apple', 'strawberry', 'waxberry', 'pitaya', 'pear', 'mango']
>   
>   fruits4 = fruits[-3:-1]
>   print(fruits4) # ['pitaya', 'pear']
>   
>   # 可以通过反向切片操作来获得倒转后的列表的拷贝
>   fruits5 = fruits[::-1]
>   print(fruits5) # ['mango', 'pear', 'pitaya', 'waxberry', 'strawberry', 'apple', 'grape']
>   ```
>
>   ==列表的排序操作==
>
>   ```py
>   list1 = ['orange', 'apple', 'zoo', 'internationalization', 'blueberry']
>   
>   # sorted函数返回列表排序后的拷贝【不会修改】传入的列表
>   list2 = sorted(list1)
>   
>   # 函数的设计就应该像sorted函数一样尽可能不产生副作用
>   list3 = sorted(list1, reverse=True)
>   
>   # 通过key关键字参数指定根据【字符串长度进行排序】而不是默认的字母表顺序
>   list4 = sorted(list1, key=len)
>   print(list1)
>   print(list2)
>   print(list3)
>   print(list4)
>   
>   # 给列表对象发出排序消息【直接在列表对象上】进行排序
>   list1.sort(reverse=True)
>   print(list1)
>   ```

>   ==还可以使用列表的**生成式**语法来创建列表==
>
>   ```py
>   import sys
>   f = [x for x in range(1, 10)]
>   print(f)
>   
>   f = [x + y for x in 'ABCDE' for y in '1234567']
>   print(f)
>   
>   # 用列表的生成表达式语法创建列表容器
>   # 用这种语法创建列表之后元素已经准备就绪所以需要耗费较多的内存空间
>   f = [x ** 2 for x in range(1, 1000)]
>   
>   # 查看对象占用内存的字节数
>   print(sys.getsizeof(f))  
>   print(f)
>   
>   # 请注意下面的代码创建的不是一个列表而是一个生成器对象
>   # 通过生成器可以获取到数据但它不占用额外的空间存储数据
>   # 每次需要数据的时候就通过内部的运算得到数据(需要花费额外的时间)
>   f = (x ** 2 for x in range(1, 1000)) # **为指数运算符，这里为x的平方
>   
>   # 相比生成式生成器不占用存储数据的空间
>   print(sys.getsizeof(f))  
>   print(f)
>   
>   for val in f:
>       print(val)
>   ```
>
>   

### 2、元组

>   Python中的元组与列表类似也是一种容器数据类型，可以用一个变量（对象）来存储多个数据，
>
>   不同之处在于**元组的元素不能修改**，在前面的代码中我们已经不止一次使用过元组了。
>
>   我们把多个元素组合到一起就形成了一个元组，所以它和列表一样可以保存多条数据

>   ```py
>   # 定义元组
>   t = ('神仙', 38, True, '四川成都')
>   print(t)
>   
>   # 获取元组中的元素
>   print(t[0])
>   print(t[3])
>   
>   # 遍历元组中的值
>   for member in t:
>       print(member)
>       
>   # 重新给元组赋值
>   # t[0] = '王大锤'  # TypeError
>   
>   # 变量t重新引用了新的元组原来的元组将被垃圾回收
>   t = ('王大锤', 20, True, '云南昆明')
>   print(t)
>   
>   # 将元组转换成列表
>   person = list(t)
>   print(person)
>   
>   # 列表是可以修改它的元素的
>   person[0] = '李小龙'
>   person[1] = 25
>   print(person)
>   
>   # 将列表转换成元组
>   fruits_list = ['apple', 'banana', 'orange']
>   fruits_tuple = tuple(fruits_list)
>   print(fruits_tuple)
>   ```
>
>   

>   ==关于为什么需要元组==
>
>   1.  元组中的元素是无法修改的，事实上我们在项目中尤其是多线程环境中可能更喜欢使用的是那些不变对象
>       -   一方面因为对象状态不能修改，所以可以避免由此引起的不必要的程序错误，
>       -   简单的说就是一个不变的对象要比可变的对象更加容易维护；
>       -   另一方面因为没有任何一个线程能够修改不变对象的内部状态，一个不变对象自动就是线程安全的，这样就可以省掉处理同步化的开销。一个不变对象可以方便的被共享访问
>       -   **所以结论就是：如果不需要对元素进行添加、删除、修改的时候，可以考虑使用元组，当然如果一个方法要返回多个值，使用元组也是不错的选择**。
>   2.  元组在创建时间和占用的空间上面都优于列表。
>       -   我们可以使用sys模块的getsizeof函数来检查存储同样的元素的元组和列表各自占用了多少内存空间，这个很容易做到。
>       -   我们也可以在ipython中使用魔法指令%timeit来分析创建同样内容的元组和列表所花费的时间

### 3、集合

>   ==集合不允许有重复元素，而且可以进行交集、并集、差集等运算==
>
>   **可以按照下面代码所示的方式来创建和使用集合**
>
>   ```py
>   # 创建集合的字面量语法
>   set1 = {1, 2, 3, 3, 3, 2}
>   print(set1)
>   print('Length =', len(set1))
>   
>   # 创建集合的构造器语法
>   set2 = set(range(1, 10))
>   set3 = set((1, 2, 3, 3, 2, 1))
>   print(set2, set3)
>   
>   # 创建集合的推导式语法(推导式也可以用于推导集合)
>   set4 = {num for num in range(1, 100) if num % 3 == 0 or num % 5 == 0}
>   print(set4)
>   
>   ----------------------------------------------------------------------
>   # 向集合添加元素和从集合删除元素
>   
>   set1.add(4)
>   set1.add(5)
>   set2.update([11, 12])
>   set2.discard(5)
>   if 4 in set2:
>       set2.remove(4)
>       
>   print(set1, set2)
>   print(set3.pop())
>   print(set3)
>   ```
>
>   

>   **集合的成员、交集、并集、差集等运算**
>
>   ```py
>   # 集合的交集、并集、差集、对称差运算
>   print(set1 & set2)  # == print(set1.intersection(set2))
>   
>   print(set1 | set2)	# == print(set1.union(set2))
>   
>   print(set1 - set2)	# == print(set1.difference(set2))
>   
>   print(set1 ^ set2)	# == print(set1.symmetric_difference(set2))
>   
>   # 判断子集和超集
>   print(set2 <= set1)	# == print(set2.issubset(set1))
>   
>   print(set3 <= set1)	# == print(set3.issubset(set1))
>   
>   print(set1 >= set2)	# == print(set1.issuperset(set2))
>   
>   print(set1 >= set3)	# == print(set1.issuperset(set3))
>   
>   ```
>
>   

### 4、字典

>   字典是另一种可变容器模型，
>
>   Python中的字典跟我们生活中使用的字典是一样一样的，
>
>   **它可以存储任意类型对象，与列表、集合不同的是，字典的每个元素都是由一个键和一个值组成的“键值对”，键和值通过冒号分开**。
>
>   **下面的代码演示了如何定义和使用字典**
>
>   ```py
>   # 创建字典的字面量语法
>   scores = {'骆昊': 95, '白元芳': 78, '狄仁杰': 82}
>   print(scores)
>   
>   # 创建字典的构造器语法
>   items1 = dict(one=1, two=2, three=3, four=4)
>   
>   # 通过zip函数将两个序列压成字典
>   items2 = dict(zip(['a', 'b', 'c'], '123'))
>   
>   # 创建字典的推导式语法
>   items3 = {num: num ** 2 for num in range(1, 10)}
>   print(items1, items2, items3)
>   
>   # 通过键可以获取字典中对应的值
>   print(scores['骆昊'])
>   print(scores['狄仁杰'])
>   
>   # 对字典中所有键值对进行遍历
>   for key in scores:
>       print(f'{key}: {scores[key]}')
>       
>   # 更新字典中的元素
>   scores['白元芳'] = 65
>   scores['诸葛王朗'] = 71
>   scores.update(冷面=67, 方启鹤=85)
>   print(scores)
>   if '武则天' in scores:
>       print(scores['武则天'])
>   print(scores.get('武则天'))
>   # get方法也是通过键获取对应的值但是可以设置默认值
>   print(scores.get('武则天', 60))
>   
>   # 删除字典中的元素
>   print(scores.popitem())
>   print(scores.popitem())
>   print(scores.pop('骆昊', 100))
>   
>   # 清空字典
>   scores.clear()
>   print(scores)
>   ```
>
>   
