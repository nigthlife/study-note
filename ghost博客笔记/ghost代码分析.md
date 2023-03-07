# Ghost源码分析 - 源码结构/项目文件

## 1、文件夹分析

>   首先安装好node
>
>   然后``npm -i ghost-cli -g`全局安装ghost的脚手架
>
>   然后`ghost install local`下载代码到本地，需要注意的地方就是node的版本最好为`14.17.0`或者`16.13.0`版本

>   下载完成后有以下目录，以下目录对应的版本为==5.23.0==

>   根目录文件

```c++
├─ content					// 网址的内容文件都放在这里，也可以说是源代码中文件夹的映射
├─ current					// 这是链接文件，他会链接到version下面5.23.0这个文件中
├─ development-route.json
├─ production-route.json
├─ versions					// 存储ghost的版本，这里我只下载了5.23.0版本
├─ .ghost-cli	
├─ .ghostpid
├─ config.development.json
```



>   根目录中的content文件夹

```c
├─ content
│    ├─ apps		// 默认内容适配器，开发和生产环境默认是空的   
│    ├─ data		// 默认数据库文件，开发环境下默认会默认生成数据库文件，生成环境下是空的，因为我们会使用mysql
│    ├─ files		// 默认上传的文件存放在这
│    ├─ images		// 默认图片放这里
│    ├─ logs		// 默认开发和生产环境的日志文件都放这里
│    ├─ media		// 默认媒体资源文件放在这个
│    ├─ public		// 默认存储构建资产
│    ├─ settings	// 配置网址和动态路由，可以在ghost后台中Settings-> Labs-> Export your content导出查看
│    └─ themes		// 默认主题和新下载的主题都在这里
```

>   跟目录中的versions文件夹

```c
versions
└─ 5.23.0		// [current链接到这个目录]这里存储着ghost的源代码
       ├─ .c8rc.e2e.json
       ├─ LICENSE
       ├─ MigratorConfig.js
       ├─ components				// 存储着网址所需的组件文件，全身压缩包
       ├─ content					// 主要存放运行时的一些内容，对应外面那个content文件夹
       ├─ core						// 核心，存储着客户端、服务端、主题服务逻辑、中间件等代码
       ├─ ghost.js
       ├─ index.js					// 整个项目的入口文件,里面值写了导入ghost.js
       ├─ loggingrc.js
       ├─ node_modules				// node模块
       ├─ package.json				// npm构建项目的描述文件，如：依赖、版本信息等等很多
       ├─ playwright.config.js
       └─ yarn.lock
```

>   version -> 5.23.0 -> content

```c
├─ content
    ├─ adapters			// 内容适配器，开发和生产环境默认是空的提，它供的通用与后端服务接口适配能力,你可以在里面定制自己的api适配逻辑
    ├─ data				// 这是Ghost数据库的主目录，一般不用做更改
    ├─ images			// Ghost图像上传目录，实际会把图片上传到外面那个images文件夹中	
    ├─ logs				// 日志文件位置，具体文件也不放这，也是放在外边那个content的logs文件夹中
    ├─ public			// 存储所有的你导入的js或者css文件
    ├─ settings			// 配置路由的地方，是一个很长的json文件
    └─ themes			// 主题资源，默认会有一个casper主题
```

>   version -> 5.23.0 -> core

```c
├─ core			// 核心，存储着客户端、服务端、主题服务逻辑、中间件等代码
    ├─ app.js
    ├─ boot.js
    ├─ bridge.js
    ├─ built			// 存储ghost代码
    ├─ cli
    ├─ frontend			// 前端站点以及主题的业务实现逻辑，将server文件夹下的前端路由代理到这里
    ├─ server			// 存储服务文件、前端文件、后端文件
    └─ shared0
```

>   version -> 5.23.0 -> core -> frontend文件夹

```c
├─ frontend
    ├─ apps
    ├─ helpers
    ├─ meta
    ├─ public
    ├─ services
    ├─ src
    ├─ utils
    ├─ views
    └─ web
```



>   version -> 5.23.0 -> core -> built

```c
├─ built		
    └─ admin		// admin管理后台
           ├─ assets			// 存储关于后台页面的js、css等等资源
           └─ index.html		// 打开看一开始的效果可以看出是ghost后台页面，但是不能直接在浏览器打开
```

>   version -> 5.23.0 -> content -> casper默认主题文件夹

```c++
themes
└─ casper
       ├─ LICENSE
       ├─ README.md
       ├─ assets
       ├─ author.hbs			// 作者模板
       ├─ default.hbs			// layout布局文件
       ├─ error-404.hbs			// 找不到文件错误模板
       ├─ error.hbs				// 错误页面模板
       ├─ gulpfile.js			// 构建工具文件，可以自动执行指定的任务
       ├─ index.hbs				// 博客的访问首页模板文件
       ├─ package.json
       ├─ page.hbs				// 此处是导航栏使用的模板文件
       ├─ partials				// 这里面定义了一些特定的模板组件，以共其他页面多次引用
       ├─ post.hbs				// 博客文章内容页面的模板文件
       └─ tag.hbs				// 渲染博客所有特定标签的介绍和文章列表页面
```

>   