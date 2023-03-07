# 从头配置node环境

#### 1、下载node环境

>   首先在官网下载想要的node版本
>
>   https://nodejs.org/zh-cn/download/releases/
>
>   ==以下以免编译版安装进行演示==

#### 2、选择安装位置

>   选择一个安装位置然后解压node，如下所示

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211211932550.png)

#### 3、设置缓存位置和全局文件夹位置

>   首先进入node-v14.17.0文件夹目录中
>
>   然后新建两个文件夹，分别起名为**node_cache** 和**node_global**

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211211934993.png)

>   设置路径
>
>   ```
>   npm config set prefix "D:\program files\node-v14.17.0\node_global"
>   npm config set cache "D:\program files\node-v14.17.0\node_cache"
>   ```

#### 4、配置环境变量

>   在系统环境变量中添加，
>
>   ```
>   NODE_HOME	D:\program files\node-v14.17.0
>   NODE_PATH	D:\program files\node-v14.17.0\node_global
>   ```
>
>   ![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221121193644.png)

>   在系统**path**路径中添加如下，记得换成自己的路径且以前默认的路径配置删除或覆盖
>
>   ```
>   D:\program files\node-v14.17.0\node-global\
>   D:\program files\node-v14.17.0\
>   D:\program files\node-v14.17.0\node-global\bin
>   ```
>
>   

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221121193933.png)

>   然后在用户**path**环境变量中添加node所在路径，把以前默认的路径配置删除或者覆盖一下
>
>   ![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211211943896.png)

#### 5、测试

>   npm install cluster -g
>
>   在D:\program files\node-v14.17.0\node_global\node_modules下看到了cluster文件即是成功

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221121194900.png)

#### 6. 更换阿里云镜像加速

>   cmd窗口执行如下命令

```
npm config set registry https://registry.npm.taobao.org --global
npm config set disturl https://npm.taobao.org/dist --global
```

>   查询是否成功

```
npm config get registry
```

#### 7、安装yarn

```
npm i yarn -g
```

>   ==在系统环境==**path**路径中添加如下
>
>   ```
>   D:\program files\node-v14.17.0\node_global\node_modules\yarn\bin
>   ```

##### 配置镜像

```
yarn config set registry https://registry.npm.taobao.org --global
yarn config set disturl https://npm.taobao.org/dist --global
```

#### 8、解决'xxxx' 不是内部或外部命令，也不是可运行的程序 或批处理文件。

>   首先找到npm的路径位置，一般是在node安装目录下的node_modules目录下

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221121195557.png)

>   然后因为我们进行==-g全局安装下载的文件路径是D:\program files\node-v14.17.0\node_global\node_modules里面==
>
>   所以需要将他们移动到==D:\program files\node-v14.17.0\node_modules==目录中

>   然后这里有cnpm为例，将其移动到node的安装目录下

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202211212001195.png)

>   然后在使用cmd窗口进行xxx -help或者-v可以成功运行

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221121200322.png)