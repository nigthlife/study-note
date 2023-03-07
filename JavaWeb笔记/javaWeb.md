# javaWeb

[TOC]



------

> 软件架构：
>
> c/s:
>
> 优点：用户体验好
>
> 缺点：开发需要开发俩个端，需要安装，部署也比较，还有维护
>
> b/s：
>
> 优点：开发只需开发一套，安装便捷，部署快，维护便利
>
> 缺点：用户体验不好，硬件设施足够强大

> bin 专门用来存放 Tomcat 服务器的可执行程序 
> conf 专门用来存放 Tocmat 服务器的配置文件 
> lib 专门用来存放 Tomcat 服务器的 jar 包 
> logs 专门用来存放 Tomcat 服务器运行时输出的日记信息 
> temp 专门用来存放 Tomcdat 运行时产生的临时数据 
> webapps 专门用来存放部署的 Web 工程。 
> work 是 Tomcat 工作时的目录，用来存放 Tomcat 运行时 
> jsp 翻译为 Servlet 的源码，和 Session 序列化的目录。

## 获取当前对象

的父节点的父节点中的子节点中指定内容的值

>  var sf = $(this).parent().parent().find("td:eq(1)").text();

> 获取元标签名的方法
>
> 1、$( this ).get(0).tagName
>
> 2、$( this )[0].tagName
>
> 3、$( this ).prop("tagName")
>
> 4、$( this ).prop("nodeName")

## 1.概述

> **web开发也称为javaweb开发，是基于java语言开发的互联网项目**
>
> **网络资源**
>
> **1.静态资源**：
>
> ​		不同客户访问的数据是一样的，不变的，如音频、图片	、视频、文本文件
>
> ​		（HTML、css、JavaScript、TXT、doc）
>
> **2.动态资源**：
>
> ​		不同客户访问同一资源，显示的结果不一样（servlet jsp php）
>
> ​	**处理技术**：jsp/Servlet（java）
>
> ​		经过处理之后的数据 —> 静态资源 —> 客户端
>
> **3.客户端与服务器通讯**
>
> ​	ip或域名
>
> ​	端口
>
> ​	传输协议 tcp（连接慢  但比较稳定）  udp（连接快 但是不稳定）
>
> ​	网络协议 HTTP
>
> 服务器：安装了服务软件的计算机
>
> 服务软件：Tomcat => 处理和响应HTTP请求
>
> Tomcat：Apache组织 写出的东西是免费开源的   中小型服务软件
>
> 其他服务软件：webLogic 支持全部的javaEE规范  Oracle公司的
>
> **项目部署：**
>
> 	1. 直接讲项目文本放到Tomcat服务软件的webapps文件夹下面（必须有一个项目）
> 	2. 在conf文件夹下的server.xml中的<host>节点下面添加 <Context docBase="项目的路径" path="虚拟路径">节点
> 	3. 添加 <Context docBase="项目的路径" >节点
>
> **动态网站的项目结构**



> **web：servlet**
>
> ####web.xml配置文件
>
> ```xml
> <!-- 设置session有效时间 -->
> <session-config>
>     <!-- 设置session有效时间为15分钟 -->
>     <session-timeout>15</session-timeout>
> </session-config>
> 
> <!-- 设置初始化默认欢迎页面 -->
> <welcome-file-list>
>     <welcome-file>index.jsp</welcome-file>
> </welcome-file-list>
> ```
>
> 

##**2.HTML**

> **html (Hyper   Text    Markup   Language ) **
>
> **中文译为“超文本标记语言”，主要是通过html标记对网页中的文本，图片，声音等内容进行描述**
>
> **HTML之所以称为超文本标记语言，不仅是因为他通过标记描述网页内容，同时也由于文本中包含了所谓的“超级链接”，通过超链接可以实现网页的跳转。从而构成了丰富多彩的Web页面**

> **行标签inline**：没有高宽，也没有外边距
>
> **块标签block**
>
> **行块标签可以相互切换**

## 标签

> #####水平线标签
>
> `<hr />` 标签在 HTML 页面中创建水平线。
>
> ##### 段落标签
>
> ‘<p></p>’
>
> 不要使用空的段落标记`<p></p>`去插入一个空行，请使用`<br />` 标签换行。
>
> ##### 链接标签
>
> ‘<a href="http://www.w3school.com.cn"></a>’
>
> ##### 文本格式
>
> <b></b>加粗
>
> <strong></strong>加粗
>
> <big></big>变大
>
> <small></small>变小
>
> <i></i>斜体
>
> <em></em>强调（与斜体效果貌似一样）
>
> <sub></sub>上标（subscript）
>
> <sup></sup>下标（superscript）
>
> '<pre></pre>'预格式文本，保留空格和换行
>
> '<blockquote></blockquote>'长引用
>
> <q></q>短引用
>
> <del></del>删除线
>
> <ins></ins>下划线
>
> **<iframe\> 标签常用属性介绍:**
>
> **height**可以设置框架显示的高度
> **width**可以设置框架显示的宽度
> **name**可以定义框架的名称
> **frameborder**用来定义是否需要**显示边框**，取值为1表示需要边框
> **scrolling**用来设置框架是否需要**滚动条**，取值可以是**yes,no,auto**
> **src**用于设置框架的地址，可以使**页面地址**，也可以是**图片地址**
> **align**用于设置元素**对齐方式**，取值可以是left，right，top，middle，bottom
>
> 

#### 连接

`target`属性：可以定义被链接的文档在何处显示。

<a href="http://www.w3school.com.cn/" target="_blank">Visit W3School!</a>在新窗口打开链接。

> **文本居中**：style="text-align:center;"
>
> **文本对齐**：text-align：对齐方式
>
> **首行首字缩进**：text-indext
>
> **字与字间距**：letter-spacing
>
> **背景颜色**：background-color
>
> **左边距**：margin-left 
>
> **右边距**：margin-right
>
> **目标窗口**：target  _blank打开一个新窗口
>
> **提示文本**：title
>
> **替换文本**：alt
>
> **双引号**：&quot
>
> **行块标签**：display：inline-block
>
> **列表样式设置为空**：list-style:none  
>
> **去除a标签下划线：**text-decoration: none
>
> check
>
> select
>
> ------
>
> **class**：为html元素定义一个或多个类名，类名从样式文件引入
>
> **id**：定义元素的唯一id
>
> **style**：规定元素的行内样式（inline style）title text 规定元素的额外信息
>
> **title**：描述元素的额外信息
>
> **字体**：font-family
>
> **颜色**：color
>
> **字体大小**：font-size
>
> **文字对齐**：text-align
>
> **元素作为列表显示**：list-item
>
> ------
>
> **图像中可替换文本**：alt
>
> **高度**：height
>
> **宽度**：width
>
> **定义图像中可以点击区域**
>
> ------
>
> 

## css属性

####1.overflow:

> **设置当对象的内容超过其指定高度及宽度时如何管理内容的属性,是添加滚动条、还是隐藏剪切超出内容**

####2.



## 样式

#### 1.- 内外部样式表（外联式）

> ![image-20201112075729097](.\image-20201112075729097.png)
>
> ![image-20201112075748015](.\image-20201112075748015.png)

> **.是class属性，#是id属性，.或#号后边接样式名称**
>
> **在使用外部样式表的情况下你可以通过改变一个文件来改变整个站点的外观，每个页面使用<link>标签链接到样式表，《link》标签在head中**
>
> **也可以定义内部样式表**

#### 2.文本属性

> ![image-20201113092606209](.\image-20201113092606209.png)

#### 4.字体属性

> ![image-20201113092844316](.\image-20201113092844316.png)



```
<head>
    <link rel="stylesheet" type="text/css" href="mystyle.css" />
</head>
```



```css

/* mystyle.css 文件 */
 
hr {color: sienna;}
p {margin-left: 20px;}
body {background-image: url("images/back40.gif");}
div {
	width: 200px;
	height: 200px;
	background-color: brown;

```

> **注意：**
>
> - 外部样式表可以在任何文本编辑器中进行编辑。
> - 文件不能包含任何的 html 标签。样式表应该以 .css 扩展名进行保存。
> - 不要在属性值与单位之间留有空格。假如你使用 “margin-left: 20 px” 而不是 “margin-left: 20px” ，它仅在 IE 6 中有效，但是在 Mozilla/Firefox 或 Netscape 中却无法正常工作。
> - 在外部css文件中，属性值满足的是css语法。
> - 属性值用key: value形式赋值,value具有单位
> - 属性值之间用;隔开(一般独行分开赋值)
> - 格式: 选择器{样式块}
> - 将html与css文件建立联系:html通过link标签链接外部css(一般head中链接)

#### 2. 内部样式表（内联式）

> **使用场景：当单个文档需要特殊的样式时，就应该使用内部样式表**

```html

<head>
<style type="text/css">
 
  hr {color: sienna;}
  p {margin-left: 20px;}
  body {background-image: url("images/back40.gif");}
 
</style>
</head>
```

> **注意：**
>
> - 内联式一般创建在style标签内(style标签一般作为head的子标签)
> - 属性值需要满足的是css语法。用key: value形式赋值,value具有单位
> - 属性值之间用;隔开(一般独行分开赋值)
> - 格式: 选择器{样式块}

####3.内联样式（行间式）

> **使用场景：由于要将表现和内容混杂在一起，内联样式会损失掉样式表的许多优势。请慎用这种方法，例如当样式仅需要在一个元素上应用一次时。**

```html

<p style="color: sienna; margin-left: 20px">
This is a paragraph
</p>
```

> **注意：**
>
> - 行间式一般创建在标签头部的style属性内。
> - 属性值满足的是css语法，属性值用key: value形式赋值,value具有单位
> - 属性值之间用;隔开

####4.三种方式内容属性不冲突（不重复）

> **当三种方式没有重复属性的设定，即每一类属性，为不同位置的唯一值，则协同布局。**

#### 5. 当三种方式存在相同属性（冲突）

> **结论：当三种方式存在相同属性，则采用覆盖赋值。按照顺序从HTML文件从上到下执行，后者属性覆盖前者属性。理论上行间式作为最后一个被解析的位置。**

>  **实验一、内联式和外联式冲突，内联式位于外联式上方先解析。---  由外联式决定**

```html

<!-- html文件 -->
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>三种引入优先级</title>
 
	<style type="text/css">
		div {
			width: 100px;
			height: 100px;
			background-color: red;
		}
	</style>
	<link rel="stylesheet" type="text/css" href="1.css">
</head>
<body>
	<div></div>
</body>
</html>

/* css文件 */
div{
	width: 200px;
	height: 200px;
	background-color: green;
}
```

> **实验二、内联式和外联式冲突，外联式位于内联式上方先解析。---  由内联式决定**

```html

<!-- html文件 -->
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>三种引入优先级</title>
 
	<link rel="stylesheet" type="text/css" href="1.css">
	<style type="text/css">
		div {
			width: 100px;
			height: 100px;
			background-color: red;
		}
	</style>
	
</head>
<body>
	<div></div>
</body>
</html>


/*css文件*/
div{
	width: 200px;
	height: 200px;
	background-color: green;
}
```

>  **实验二、三种方式并存冲突。---  由行内式决定**
>
> ```html
> 
> <!-- html文件 -->
> <!DOCTYPE html>
> <html>
> <head>
> 	<meta charset="UTF-8">
> 	<title>三种引入优先级</title>
>  
> 	<link rel="stylesheet" type="text/css" href="1.css">
> 	<style type="text/css">
> 		div {
> 			width: 100px;
> 			height: 100px;
> 			background-color: red;
> 		}
> 	</style>
> 	
> </head>
> <body>
> 	<div style="width: 300px;height: 300px;background-color: yellow"></div>
> </body>
> </html>
> 
> 
> /*css文件*/
> div{
> 	width: 200px;
> 	height: 200px;
> 	background-color: green;
> }
> ```
>
> 

> **通过！important改变单个优先级**
>
> ```html
> <!-- html文件 -->
> <!DOCTYPE html>
> <html>
> <head>
> 	<meta charset="UTF-8">
> 	<title>三种引入优先级</title>
>  
> 	<link rel="stylesheet" type="text/css" href="1.css">
> 	<style type="text/css">
> 		div {
> 			width: 100px;
> 			height: 100px;
> 			background-color: red!important;
> 		}
> 	</style>
> 	
> </head>
> <body>
> 	<div style="width: 300px;height: 300px;background-color: yellow"></div>
> </body>
> </html>
> ```
>
> **注意：**
>
> 1. **适用于单个强调，多处出现important，没有任何意义。**
> 2. **仅仅首先使用带有 ‘ important ’ 的单个属性，而不是存在‘ important ’ 的应用方式。**

## 图片

> ![image-20201112075141163](.\image-20201112075141163.png)
>
> 

## 表格

http://www.w3school.com.cn/html/html_tables.asp

## 表单

文本

```html
<html>
<body>
<form>
名：
<input type="text" name="firstname">
<br />
姓：
<input type="text" name="lastname">
</form>
</body>
</html>
```

密码

```html
<html>
<body>
<form>
用户：
<input type="text" name="user">
<br />
密码：
<input type="password" name="password">
</form>
<p>
请注意，当您在密码域中键入字符时，浏览器将使用项目符号来代替这些字符。
</p>
</body>
</html>
```

单选按钮

```html
<form>
<input type="radio" name="sex" value="male" /> Male
<br />
<input type="radio" name="sex" value="female" /> Female
</form>
```

复选框

```html
<form>
<input type="checkbox" name="bike" />
I have a bike
<br />
<input type="checkbox" name="car" />
I have a car
</form>
```

表单扩展

http://www.w3school.com.cn/html/html_forms.asp

## !DOCYTYPE 声明

> 这就是`<!DOCTYPE>`的用处。
> `<!DOCTYPE>`不是 HTML 标签。它为浏览器提供一项信息（声明），即 HTML 是用什么版本编写的。
>
> `<!DOCYTYPE>`是HTML5的版本声明

## 各种元素

### HTML link 元素



> `<link>`标签定义文档与外部资源之间的关系。
> `<link>`标签最常用于连接样式表。

> <style>标签用于为 HTML 文档定义样式信息。您可以在
> <style>元素内规定 HTML 元素在浏览器中呈现的样式。

> <script>标签用于定义客户端脚本，比如 JavaScript。script 
> 元素既可包含脚本语句，也可通过 src 属性指向外部脚本文件。
> 必需的 type 属性规定脚本的 MIME 类型。JavaScript 
> 最常用于图片操作、表单验证以及内容动态更新。
>
> 



## Servlet生命周期

servlet生命周期，可参考https://blog.csdn.net/javaloveiphone/article/details/8154791

#### 1.**Servlet容器**

> 先从servlet容器说起：大家最为熟悉的servlet容器就是Tomcat 
>
> Tomcat 的容器分为四个等级，**真正管理Servlet 的容器是Context 容器**，一个 Context 对应一个 Web 工程



#### 2.**Web服务器在与客户端交互时.Servlet的工作过程是:**

> 1. 在客户端对web服务器发出请求
> 2. web服务器接收到请求后将其发送给Servlet
> 3. Servlet容器为此产生一个实例对象并调用ServletAPI中相应的方法来对客户端HTTP请求进行处理,然后将处理的响应结果返回给WEB服务器
> 4. web服务器将从Servlet实例对象中收到的响应结构发送回客户端



#### **3.Servlet生命周期**

#####**1.**创建servlet实例：**

> 在默认情况下Servlet实例是在第一个请求到来的时候创建，以后复用。如果有的Servlet需要复杂的操作需要载初始化时完成，比如打开文件、初始化网络连接等，可以通知服务器在启动的时候创建该Servlet的实例。具体配置如下：
>
>   <servlet>
>    <servlet-name>TimeServlet</servlet-name>
>    <servlet-class>com.allanlxf.servlet.basic.TimeServlet</servlet-class>
>    **<load-on-startup>1</load-on-startup>
> **  </servlet>



#####**2.初始化**

> 一旦Servlet实例被创建，Web服务器会自动调用init(ServletConfig config)方法来初始化该Servlet。其中方法参数config中包含了Servlet的配置信息，比如初始化参数，该对象由服务器创建。

###### **1.如何配置Servlet的初始化参数**

> ```xml
> <servlet>
>          <servlet-name>TimeServlet</servlet-name>
>          <servlet-class>com.allanlxf.servlet.basic.TimeServlet</servlet-class>
>         <init-param>
>             <param-name>user</param-name>
>             <param-value>username</param-value>
>        </init-param>
>        <init-param>
>            <param-name>blog</param-name>
>            <param-value>http://。。。</param-value>
>        </init-param>
>     </servlet>
> ```



##### **3.服务**

>  一旦Servlet实例成功创建及初始化，该Servlet实例就可以被服务器用来服务于客户端的请求并生成响应。在服务阶段Web服务器会调用该实例的service(ServletRequest request, ServletResponse response)方法，request对象和response对象有服务器创建并传给Servlet实例。request对象封装了客户端发往服务器端的信息，response对象封装了服务器发往客户端的信息。





##### **4.销毁**

>  当Web服务器认为Servlet实例没有存在的必要了，比如应用重新装载，或服务器关闭，以及Servlet很长时间都没有被访问过。服务器可以从内存中销毁（也叫卸载）该实例。Web服务器必须保证在卸载Servlet实例之前调用该实例的destroy()方法，以便回收Servlet申请的资源或进行其它的重要的处理。
>
>  Web服务器必须保证调用destroy()方法之前，让所有正在运行在该实例的service()方法中的线程退出或者等待这些线程一段时间。一旦destroy()方法已经执行，Web服务器将拒绝所有的新到来的对该Servlet实例的请求，destroy()方法退出，该Servlet实例即可以被垃圾回收。



#### 4.servlet解析客户端http请求流程：

> 1. **web客户向Servlet容器发出HTTP请求;**
>
> 2. **Servlet容器解析web的HTTP请求.**
>
> 3. **Servlet容器创建一个HttpRequest对象,在这个对象中封装了http请求信息;**
>
> 4. **Servlet容器创建一个HttpResponse对象;**
>
> 5. **Servlet容器（如果访问的该servlet不是在服务器启动时创建的，则先创建servlet实例并调用init()方法初始化对象）调用HttpServlet的service()方法,把HttpRequest和HttpResponse对象为service方法的参数传给HttpServlet对象;**
>
>    
>
> 6. **HttpServlet调用HttpRequest的有关方法,获取HTTP请求信息;**
>
> 7. **HttpServlet调用HttpResponse的有关方法,生成响应数据;**
>
> 8. **Servlet容器把HttpServlet的响应结果传给web客户. **

## HTTP协议

####1:HTTP协议：

可参考：https://www.cnblogs.com/ranyonsue/p/5984001.html

#### 2.主要特点

> 1、**简单快速**：客户向服务器请求服务时，只需传送请求方法和路径。请求方法常用的有GET、HEAD、POST。每种方法规定了客户与服务器联系的类型不同。由于HTTP协议简单，使得HTTP服务器的程序规模小，因而通信速度很快。
>
> 2、**灵活**：HTTP允许传输任意类型的数据对象。正在传输的类型由Content-Type加以标记。
>
> 3.**无连接**：无连接的含义是限制每次连接只处理一个请求。服务器处理完客户的请求，并收到客户的应答后，即断开连接。采用这种方式可以节省传输时间。
>
> 4.**无状态**：HTTP协议是无状态协议。无状态是指协议对于事务处理没有记忆能力。缺少状态意味着如果后续处理需要前面的信息，则它必须重传，这样可能导致每次连接传送的数据量增大。另一方面，在服务器不需要先前信息时它的应答就较快。每次请求是独立的
> 5、**支持B/S及C/S模式。**

#### 3.URL与URI

>  	从上面的URL可以看出，一个完整的URL包括以下几部分：
> 1.**协议部分：该URL的协议部分为“http：**”，这代表网页使用的是HTTP协议。在Internet中可以使用多种协议，如HTTP，FTP等等本例中使用的是HTTP协议。在"HTTP"后面的“//”为分隔符
>
> 2.**域名部分：该URL的域名部分为“www.aspxfans.com”。一个URL中，也可以使用IP地址作为域名使用**
>
> 3.**端口部分：跟在域名后面的是端口，域名和端口之间使用“:”作为分隔符。端口不是一个URL必须的部分，如果省略端口部分，将采用默认端口**
>
> 4.**虚拟目录部分：从域名后的第一个“/”开始到最后一个“/”为止，是虚拟目录部分。**虚拟目录也不是一个URL必须的部分。本例中的虚拟目录是“/news/”
>
> 5.**文件名部分**：从域名后的最后一个“/”开始到“？”为止，是文件名部分，如果没有“?”,则是从域名后的最后一个“/”开始到“#”为止，是文件部分，如果没有“？”和“#”，那么从域名后的最后一个“/”开始到结束，都是文件名部分。本例中的文件名是“index.asp”。文件名部分也不是一个URL必须的部分，如果省略该部分，则使用默认的文件名
>
> 6.**锚部分：从“#”开始到最后，都是锚部分**。本例中的锚部分是“name”。锚部分也不是一个URL必须的部分
>
> 7.**参数部分：从“？”开始到“#”为止之间的部分为参数部分，又称搜索部分、查询部分**。本例中的参数部分为“boardID=5&ID=24618&page=1”。参数可以允许有多个参数，参数与参数之间用“&”作为分隔符。
>
> **URI和URL的区别:**
>
> RI，是uniform resource identifier，**统一资源标识符，用来唯一的标识一个资源。**
>
> URL是uniform resource locator，**统一资源定位器，它是一种具体的URI，**
>
> 即URL可以用来标识一个资		**源，而且还指明了如何locate这个资源***。
>
> URN，uniform resource name，**统一资源命名，是通过名字来标识资源**，
>
> 比如mailto:java-net@		 java.sun.com。

#### 4.HTTP组成内容

**HTTP是一个基于TCP/IP通信协议来传递数据（HTML 文件, 图片文件, 查询结果等）。**

**HTTP默认端口80**



> **HTTP请求协议内容：**
>
> **请求行（request line）、请求头部（header）、请求空行和请求数据四个部分组成。**
>
> **请求行：（请求方式 请求地址 HTTP/协议的版本）**
>
> **请求头：（键值对信息，格式：键值）**
>
> **请求空行**
>
> **请求正文或者数据：（get请求一般没有参数数据，post可能有参数信息写在正文中）**
>
> 
>
> **响应内容：**
>
> **第一部分：状态行，由HTTP协议版本号， 状态码， 状态消息 三部分组成。**
>
> **第二部分：消息报头，用来说明客户端要使用的一些附加信息**
>
> **第三部分：空行，消息报头后面的空行是必须的**
>
> **第四部分：响应正文，服务器返回给客户端的文本信息。**
>
> 
>
> **状态码**
>
> **1xx：指示信息											--表示请求已接收，继续处理**
>
> **2xx：成功	  										--表示请求已被成功接收、理解、接受**
>
> **3xx：重定向   										--要完成请求必须进行更进一步的操作**
>
> **4xx：客户端错误（url地址资源不存在）					--请求有语法错误或请求无法实现**
>
> **5xx：服务器端错误（大部分情况都是代码的问题）	--服务器未能实现合法的请求**

> **会话技术：在多次请求中共享数据**
>
> **客户端会话技术（cookie）**
>
> **服务器会话技术（session）**



## JSP技术

#### 1.jsp生命周期

> **1.编译阶段：servlet容器编译servlet源文件，生成servlet类**
>
> **2.初始化阶段：加载与JSP对应的servlet类，创建实例，并调用初始化方法**
>
> **3.执行阶段：调用与JSP对应的servlet实例的服务方式**
>
> **4.销毁阶段：调用与JSP对应的servlet实例的销毁方法，然后销毁servlet实例；**

> **解析jsp文件、将jsp文件转化为servlet、编译servlet文件**
>
> **1.当浏览器发起请求时，jsp引擎将编译jsp文件**
>
> **其中，前三个阶段是将JSP文件转换为Servlet类并装载和创建该类实例**
>
> **当JSP页面被访问时，Web容器容器解析JSP文件并转为相应的Java文件，然后编程为.class文件**
>
> **2.jsp初始化、调用jspInit（）方法**
>
> **这里，首先判断是不是第一次请求，如果是的话，也就是说JSP还没有被编译过，***
>
> ***JSP引擎就把相应的JSP文件编译成servlet，生成字节码文件，并调用jspInit()；**
>
> **如果不是第一次请求，说明已经有了字节码文件，那么就开始解析执行，调用jspServive()。**
>
> **3.当jsp页面初始化后，调用JSPService（）方法执行**
>
> **4.jspDestroy()方法销毁、等价于servlet中的销毁方法**



## **过滤器**

#### **1.过滤器**

> 





## 会话

####**1.Cookie**

####1.概念

> HTTP Cookie（也叫 Web Cookie或浏览器 Cookie）是服务器发送到用户浏览器并保存在本地的一小块数据，它会在浏览器下次向同一服务器再发起请求时被携带并发送到服务器上。通常，它用于告知服务端两个请求是否来自同一浏览器，如保持用户的登录状态。Cookie 使基于无状态的 HTTP 协议记录稳定的状态信息成为了可能。
>
> Cookie 主要用于以下三个方面：
>
> - 会话状态管理（如用户登录状态、购物车、游戏分数或其它需要记录的信息）
> - 个性化设置（如用户自定义设置、主题等）
> - 浏览器行为跟踪（如跟踪分析用户行为等）

#### **2.Session**

> Session 代表着服务器和客户端一次会话的过程。Session 对象存储特定用户会话所需的属性及配置信息。这样，当用户在应用程序的 Web 页之间跳转时，存储在 Session 对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当客户端关闭会话，或者 Session 超时失效时会话结束

#### **3.Cookie 和 Session 有什么不同？**

> - **作用范围不同**，Cookie 保存在客户端（浏览器），Session 保存在服务器端。
> - **存取方式的不同**，Cookie 只能保存 ASCII，Session 可以存任意数据类型，一般情况下我们可以在 Session 中保持一些常用变量信息，比如说 UserId 等。
> - **有效期不同**，Cookie 可设置为长时间保持，比如我们经常使用的默认登录功能，Session 一般失效时间较短，客户端关闭或者 Session 超时都会失效。
> - **隐私策略不同**，Cookie 存储在客户端，比较容易遭到不法获取，早期有人将用户的登录名和密码存储在 Cookie 中导致信息被窃取；Session 存储在服务端，安全性相对 Cookie 要好一些。
> - **存储大小不同**， 单个 Cookie 保存的数据不能超过 4K，Session 可存储数据远高于 Cookie

>   **当用户禁用cookie时我们使用`responsee.encodeURL("url")`来获取url更加方便,并且也更加的智能,当用户禁用了`Cookie`的时候,我们才会把`jsessionid` 拼接上去,如果没有的话,我们的`url`还是最简洁的方式呈现.**



#### **4.为什么需要 Cookie 和 Session，他们有什么关联**

> 浏览器是没有状态的(HTTP 协议无状态)，这意味着浏览器并不知道是张三还是李四在和服务端打交道。这个时候就需要有一个机制来告诉服务端，本次操作用户是否登录，是哪个用户在执行的操作，那这套机制的实现就需要 Cookie 和 Session 的配合

> 用户第一次请求服务器的时候，服务器根据用户提交的相关信息，创建创建对应的 Session ，请求返回时将此 Session 的唯一标识信息 SessionID 返回给浏览器，浏览器接收到服务器返回的 SessionID 信息后，会将此信息存入到 Cookie 中，同时 Cookie 记录此 SessionID 属于哪个域名

> 当用户第二次访问服务器的时候，请求会自动判断此域名下是否存在 Cookie 信息，如果存在自动将 Cookie 信息也发送给服务端，服务端会从 Cookie 中获取 SessionID，再根据 SessionID 查找对应的 Session 信息，如果没有找到说明用户没有登录或者登录失效，如果找到 Session 证明用户已经登录可执行后面操作

> **根据以上流程可知，SessionID 是连接 Cookie 和 Session 的一道桥梁，大部分系统也是根据此原理来验证用户登录状态**

#### **5.如果浏览器中禁止了 Cookie，如何保障整个机制的正常运转**

> 第一种方案，**每次请求中都携带一个 SessionID 的参数**，也可以 Post 的方式提交，也可以在请求的地址后面拼接

> 第二种方案，**Token 机制**。Token 机制多用于 App 客户端和服务器交互的模式，也可以用于 Web 端做用户状态管理

#### **6.扩展：(分布式session问题)[]**

[如何考虑分布式 Session 问题？][https://www.cnblogs.com/ityouknow/p/10856177.html]



## 防盗链与验证码

#### **1.什么是盗链**

> 客户端向服务器请求资源时，为了减少网络带宽，提升响应时间，服务器一般不会一次将所有  资源完整地传回给客户端。比如在请求一个网页时，首先会传回该网页的文本内容，当客户端  浏览器在解析文本的过程中发现有图片存在时，会再次向服务器发起对该图片资源的请求，服  务器将存储的图片资源再发送给客户端。在这个过程中，如果该服务器上只包含了网页的文本  内容，并没有存储相关的图片资源，而是将图片资源链接到其他站点的服务器上，就形成了盗  链行为
>
> 
>
> **referer**
>
> HTTP Referer是header的一部分，当浏览器向web服务器发送请求的时候，一般会带上Referer，告诉服务器我是从哪个页面链接过来的，服务器藉此可以获得一些信息用于处理。通过该头域的值，我们可以检测到访问目标资源的源地址

> 作者：zhllsr
> 链接：https://www.jianshu.com/p/c02064db8b5b
> 来源：简书
> 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。

#### **2.验证码技术**

> 验证码从设计之初就是为了区分人与计算机，计算机识别难度较大，而人可以轻易识别，常用于身份校验、交易确认等关键环节。当下的网络生产生活中：暴力猜测登陆、暴力破解密码、垃圾广告、灌水等在网络中泛滥，不仅消耗了大量的服务器资源，同时也可能威胁到服务器的安全，因此，验证码作为一种实用高效技术被大量使用起来。

##### 传统输入式验证码

- [ ] 主要是通过用户输入图片中的字母、数字、汉字等进行验证。
- [ ] 原理：向服务端请求，生成随机的字符，写入会话请求，同时将随机字符生成对应图片，响应给前端；前端输入对应字符的验证码，向后台发起校验。
- [ ] 特点：简单易操作，人机交互性较好。但安全系数低，容易被破解。采用OCR技术可轻松破解。

[扩展其他验证码][https://zhuanlan.zhihu.com/p/38307869]



## 文件上传与下载

#### **1.文件上传的细节**

> **1、为保证服务器安全，上传文件应该放在外界无法直接访问的目录下，比如放于WEB-INF目录下。**
>
> 　　**2、为防止文件覆盖的现象发生，要为上传文件产生一个唯一的文件名。**
>
> 　　**3、为防止一个目录下面出现太多文件，要使用hash算法打散存储。**
>
> 　　**4、要限制上传文件的最大值。**
>
> 　　**5、要限制上传文件的类型，在收到上传文件名时，判断后缀名是否合法。**

#### **2.原理**

> - 提供form表单，method必须是post
>
> - form表单的enctype必须是multipart/form-data
>
> - 提供input type=”file”
>
> - ### Enctype属性
>
> - 告知服务器请求正文的MIME类型。
>
> - application/x-www-form-urlencoded(默认):
>   正文：name=aa&password=123
>   服务器获取数据:request.getParameter(“name”);
>
> - 

####[扩展][https://developer.aliyun.com/article/227660]

#### **文件上传优化限制**

> 1、把保存的文件放在用户无法直接访问到的地方：例如放在：在WEB-INF/files目录中。
>
> ```java
>  String storeDirectoryRealPath=getServletContext().getRealPath("/WEB-INF/files");
> ```
>
> 2、让文件名唯一。
>
> ```java
> String guidFilename=GUIDUtil.generateGUID()+"_"+filename;
>             //构建输出流
>             OutputStream  out=new FileOutputStream(new File(storeDirectory,guidFilename));
> ```
>
> 3、避免同一个文件夹中的文件过多。
> 3.1按照日期进行存储。
>
> ```java
>   String childDirectory=makeChileDirectory(storeDirectory);
> 
>     private String makeChileDirectory(File storeDirectory) {
>         Date now=new Date();
>         DateFormat df=new SimpleDateFormat("yyyy-MM-dd");
>         String sdate=df.format(now);
>         File f=new File(storeDirectory,sdate);
>         if(!f.exists()){
>             f.mkdirs();
>         }
>         return sdate;
>     }
> ```
>
> 3.2用文件名的hashCode计算需要进行存储的目录，二级目录。
>
> ```java
>   private String makeChildDirectory(File storeDirectory, String guidFilename) {
>         int hashCode = guidFilename.hashCode();
>         int dir1 = hashCode&0xf;//  0~15
>         int dir2 = (hashCode&0xf0)>>4;//0~15
> 
>         String s = dir1+File.separator+dir2;
> 
>         File f = new File(storeDirectory,s);
>         if(!f.exists()){
>             f.mkdirs();
>         }
>         return s;
>     }
> ```
>
> 4、限制文件的大小。web方式不适合上传大的文件。
> 4.1单个文件大小：
>
> ```java
> ServletFileUpload  sfu=new ServletFileUpload(factory);
>         sfu.setFileSizeMax(4*1024*1024);//限制不超过4M
> ```
>
> 4.2总文件大小：多文件上传
>
> ```java
>  ServletFileUpload  sfu=new ServletFileUpload(factory);
>     sfu.setSizeMax(8*1024*1024);//总文件大小
> ```
>
> 5、限制文件的上传类型。
> 5.1通过文件扩展名来进行限制。
>
> ```java
>  String extensionName=FilenameUtils.getExtension(filename);
> ```
>
> 5.2通过文件MIME类型来限制。
>
> ```java
>     String mimeType=item.getContentType();
> ```
>
> 6、空文件上传解决方案。
> 判断文件名是否为空，当文件名为空时return。
>
> 
>
> 7、临时文件
> DiskFileItemFactory的作用是产生FileItem对象。其内部有一个缓存，默认大写拾10kb，如果上传文件超过10kb，则用磁盘作为缓存。存放缓存的目录默认是系统的临时目录。
>
> ```java
> DiskFileItemFactory factory=new DiskFileItemFactory();
>         //更改临时文件的存放目录
>         factory.setRepository(new File("D:/"));
> ```
>
> 如果是自己用IO流实现的文件上传，则需要在流关闭后，清理临时文件。
>
> ```java
>   FileItem.delete();
> ```
>
> 8、中文编码
>
> ```java
>  request.setCharacterEncoding("UTF-8");
> 
>     //该编码要和jsp页面保持一致
>     String fieldValue=item.getString("UTF-8");
> ```
>
> 9、动态js控制上传框
>
> ```javascript
>   <form action="${pageContext.request.contextPath}/servlet/UploadServlet3" method="post" enctype="multipart/form-data">
>         name:<input type="text" name="name"/><br/>
>         <div id="d1">
>             <div>
>             photo:<input type="file" name="photo"/><input type="button" value="继续上传" onclick="addFile()"/>
>             </div>
>         </div>
>         <input type="submit" value="上传"/>
>     </form>
>     <script type="text/javascript">
>         function addFile(){
>             var d1 = document.getElementById("d1");
>             var oldInnerHtml = d1.innerHTML;
>             d1.innerHTML=oldInnerHtml+"<div>photo:<input type='file' name='photo'/><input type='button' value='删除' onclick='deleteOne(this)'/></div>";
>         }
>         function deleteOne(delBtn){
>             delBtn.parentNode.parentNode.removeChild(delBtn.parentNode);
>         }
>     </script>
> ```
>
> 



## 同步请求与异步请求

#### **0.先解释一下同步和异步的概念jav**

> 同步是指：发送方发出数据后，等接收方发回响应之后才发下一个数据包的通信方式。  
> 异步是指：发送方发出数据后，不等接收方发回响应，接着发送下个数据包的通信方式。



#### **1.同步请求原理**

> 当浏览器向服务器发送同步请求时，服务处理同步请求的过程中，浏览器会处于等待的状态，服务器处理完请求**把数据响应给浏览器并覆盖浏览器内存中原有的数据**，浏览器——**重新加载页面并展示服务器响应的数据**。

#### **2.异步请求原理**

> 浏览器把请求交给**代理对象**—XMLHttpRequest（绝大多数浏览器都内置了这个对象），**由代理对象向服务器发起请求，接收、解析服务器响应的数据**，并把数据更新到浏览器指定的控件上。从而实现了页面数据的局部刷新

#### **3.区别**

> 在同步请求/响应通讯模型中，老是浏览器（与 Web 服务器、应用服务器或 Web 应用程序相对）发起请求（经过 Web 用户）。接着，Web 服务器、应用服务器或 Web 应用程序响应进入的请求。在处理同步请求/响应对期间，用户不能继续使用浏览器。
>
>  
>
> 在异步请求/响应通讯模型中，浏览器（经过 Web 用户）到 Web 服务器、应用服务器或 Web 应用程序的通讯（以及反过来）是解耦的。在异步请求/响应对的处理中，Web 用户在当前异步请求被处理时还能够继续使用浏览器。一旦异步请求处理完成，异步响应就被通讯（从 Web 服务器、应用服务器或 Web 应用程序）回客户机页面。典型状况下，在这个过程当中，调用对 Web 用户没有影响；他们不须要等候响应。

[原文地址][https://blog.csdn.net/weixin_36691991/article/details/88929136]



## [JSON的定义与标准语法][https://blog.csdn.net/superit401/article/details/49999031]

####1.点击标题



##[Ajax异步请求][https://www.cnblogs.com/qianguyihao/p/8485028.html]

#### 1.点击标题



## CSS选择器

#### **0.备注**

> **暂时没有能够选择 父元素、父元素的同级元素，或 父元素的同级元素的子元素 的选择器或者组合器。**

####**1.[基本选择器](https://developer.mozilla.org/zh-CN/docs/Web/CSS/CSS_Selectors#基本选择器)**

> **1.通用选择器**
>
> 选择所有元素。（可选）可以将其限制为特定的名称空间或所有名称空间。
> **语法：**`*` `ns|*` `*|*`
> **例子：**`*` 将匹配文档的所有元素。
>
> 1
>
> **2.元素选择器**
>
> 按照给定的节点名称，选择所有匹配的元素。
> **语法：**`elementname`
> **例子：**`input` 匹配任何 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/input) 元素。
>
> 1
>
> **3.类选择器**
>
> 按照给定的 `class` 属性的值，选择所有匹配的元素。
> **语法**：`.classname`
> **例子**：`.index` 匹配任何 `class` 属性中含有 "index" 类的元素。
>
> 1
>
> **4.ID选择器**
>
> 按照 `id` 属性选择一个与之匹配的元素。需要注意的是，一个文档中，每个 ID 属性都应当是唯一的。
> **语法：**`#idname`
> **例子：**`#toc` 匹配 ID 为 "toc" 的元素。
>
> 1
>
> **5.属性选择器**
>
> 按照给定的属性，选择所有匹配的元素。
> **语法：**`[attr]` `[attr=value]` `[attr~=value]` `[attr|=value]` `[attr^=value]` `[attr$=value]` `[attr*=value]`
> **例子：**`[autoplay]` 选择所有具有 `autoplay` 属性的元素（不论这个属性的值是什么）。

####**2.分组选择器**

> **1.选择器列表**
>
> `,` 是将不同的选择器组合在一起的方法，它选择所有能被列表中的任意一个选择器选中的节点。
> **语法**：`A, B`
> **示例**：`div, span` 会同时匹配 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/span) 元素和 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/div) 元素。

#### **3.组合器**

> **1.后台组合器**
>
> ` `（空格）组合器选择前一个元素的后代节点。
> **语法：**`A B`
> **例子：**`div span` 匹配所有位于任意 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/div) 元素之内的 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/span) 元素。
>
> 1
>
> **2.直接子代组合器**
>
> `>` 组合器选择前一个元素的直接子代的节点。
> **语法**：`A > B`
> **例子**：`ul > li` 匹配直接嵌套在 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/ul) 元素内的所有 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/li) 元素。
>
> 1
>
> **3.一般兄弟组合器**
>
> `~` 组合器选择兄弟元素，也就是说，后一个节点在前一个节点后面的任意位置，并且共享同一个父节点。
> **语法**：`A ~ B`
> **例子**：`p ~ span` 匹配同一父元素下，[``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/p) 元素后的所有 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/span) 元素。
>
> 1
>
> **4.紧邻兄弟组合器**
>
> `+` 组合器选择相邻元素，即后一个元素紧跟在前一个之后，并且共享同一个父节点。
> **语法：**`A + B`
> **例子：**`h2 + p` 会匹配所有紧邻在 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/h2) 元素后的 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/p) 元素。
>
> 1
>
> **5.列组合器**
>
> `||` 组合器选择属于某个表格行的节点。
> **语法：** `A || B`
> **例子：** `col || td` 会匹配所有 作用域内的<td>元素。

#### **4.伪选择器**

> **1.伪类**
>
> `:` 伪选择器支持按照未被包含在文档树中的状态信息来选择元素。
> **例子：**`a:visited` 匹配所有曾被访问过的 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/a) 元素。
>
> 
>
> **2.伪元素**
>
> `::` 伪选择器用于表示无法用 HTML 语义表达的实体。
> **例子：**`p::first-line` 匹配所有 [``](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/p) 元素的第一行。

####[资料来源][https://developer.mozilla.org/zh-CN/docs/Web/CSS/CSS_Selectors#%E5%9F%BA%E6%9C%AC%E9%80%89%E6%8B%A9%E5%99%A8]



## **CSS样式优先级**

####**1.什么是选择器优先级**

> 浏览器通过**优先级**来判断哪一些属性值与一个元素最为相关，从而在该元素上应用这些属性值。优先级是基于不同种类[选择器](https://developer.mozilla.org/en/CSS/CSS_Reference#Selectors)组成的匹配规则。

####**2.优先级的计算规则**

> **内联 > ID选择器 > 类选择器 > 标签选择器。**

> 优先级是由 `A` 、`B`、`C`、`D` 的值来决定的，其中它们的值计算规则如下：
>
> 1. 如果存在内联样式，那么 `A = 1`, 否则 `A = 0`;
> 2. `B` 的值等于 `ID选择器` 出现的次数;
> 3. `C` 的值等于 `类选择器` 和 `属性选择器` 和 `伪类` 出现的总次数;
> 4. `D` 的值等于 `标签选择器` 和 `伪元素` 出现的总次数 。
>
>
> 作者：chess
> 链接：https://juejin.cn/post/6844903709772611592

####**3.比较两个优先级的高低**

>  **比较规则是: 从左往右依次进行比较 ，较大者胜出，如果相等，则继续往右移动一位进行比较 。如果4位全部相等，则后面的会覆盖前面的**

####**4.优先级的特殊情况(!important**)**

> 经过上面的优先级计算规则，我们可以知道内联样式的优先级是最高的，但是外部样式有没有什么办法覆盖内联样式呢？有的，那就要**!important**` 出马了。因为一般情况下，很少会使用内联样式 ，所以 `!important` 也很少会用到！如果不是为了要覆盖内联样式，建议尽量不要使用 `!important` 。、
>
> **千万不要在内联样式中使用 !important**