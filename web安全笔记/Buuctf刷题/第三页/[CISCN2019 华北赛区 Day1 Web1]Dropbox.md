#[CISCN2019 华北赛区 Day1 Web1]Dropbox

## 0、知识点与工具









## 、解题

>   首先，打开网页页面，开始分析，有一个登陆，测试一波发现并发现什么东西，
>
>   然后查看源代码，和抓包也没发现啥有用的

>   然后有注册按钮，直接注册

>   随便输点内容注册

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091143319.png)

>   注册完成后，登陆进去，界面如下，那么就可以暂且排除登陆框那有注入点了

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091144182.png)

>   然后随便上传一个文件，上传成功后会有删除和下载按钮
>
>   **下载按钮，可能会有任务文件下载漏洞，可以测试一下**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091146497.png)

>   点击删除抓包，然后把filename的参数改成index.php试试

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091148740.png)

>   结果是文件不存在，
>
>   这说明当前文件里没有这个文件，可以判断当前这个文件是存放我们上传文件的文件夹
>
>   可以尝试【../】往上一层目录测试找找看

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091150801.png)

>   最后在【../../】这里找到index.php

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091153547.png)

>   如此可见存在任意文件下载漏洞，那么就阔以把我们看见的.php全搞出来

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfimg/web/three202303091157046.png)