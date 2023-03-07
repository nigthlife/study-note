





## 0、前言

官方文档：https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc

微信文档：

【1 什么是SpringMVC】https://mp.weixin.qq.com/s/yuQqZzAsCefk9Jv_kbh_eA

【2 第一个MVC程序】https://mp.weixin.qq.com/s/8ddT6FD0Y4f3XdbEz0aqpQ

【3 RestFul和控制器】https://mp.weixin.qq.com/s/3EtyzJohOVGz62nEYLhKHg

【4 数据处理及跳转】https://mp.weixin.qq.com/s/1d_PAk2IIp-WWX2eBbU3aw

【5 整合SSM框架】https://mp.weixin.qq.com/s/SDxqGu_il3MUCTcN1EYrng

【6 Json交互处理】https://mp.weixin.qq.com/s/RAqRKZJqsJ78HRrJg71R1g

【7 Ajax研究】https://mp.weixin.qq.com/s/tB4YX4H59wYS6rxaO3K2_g

【8 拦截器+文件上传下载】https://mp.weixin.qq.com/s/NWJoYiirbkSDz6x01Jji3g



## 1、什么是MVC

-   **MVC不是一种设计模式，MVC是一种架构模式**
-   **MVC是模型(Model)、视图(View)、控制器(Controller)的简写，是一种软件设计规范**
-   **MVC主要作用是降低了视图与业务逻辑间的双向耦合**



>   **Model（模型）：数据模型，提供要展示的数据，因此包含数据和行为，可以认为是领域模型或JavaBean组件**
>
>   
>
>   **View（视图）：负责进行模型的展示，也就是用户界面**
>
>   
>
>   **Controller（控制器）：接收用户请求，委托给模型进行处理，处理完毕后把返回的模型数据返回给视图，由视图负责展示，控制器做了调度员的工作**



>   ssm：Mybatis + Spring + SpringMVC  
>
>   
>
>   之后学习计划：
>
>   SpringMVC + Vue + SpringBoot + SpringCloud + linux

vo对视图类进一步划分

**SpringMVC干了什么事情**

>   1、用户开始发起请求，也就是在浏览器地址回车的那一瞬间，然后开始寻找前端控制器，也就是DispatchServlet
>
>   然后用户发出的所有请求都会别它接收或拦截，前提是web配置好匹配所有请求，假设请求url为http:localhost:8080/Spring/hello, 首先http:locahost:8080这是服务器域名，然后Spring为部署在服务器上的web站点，hello表示控制器，所有url的意义为请求位于服务器localhost:8080上的Spring站点的hello控制器
>
>   然后DispatchServlet会调用HandlerMapper处理器映射器，也就是根据url控制器（hello）寻找一个Handler处理器
>
>   其中HandlerExecution表示具体的Handler，它会去根据url去查找控制器（controller）如：上述url被查找的控制器为hello，找到后，HandlerExecution将解析后的信息传递给DispatchServlet，然后这个时候DispatchServlet已经拿到了这个请求的处理器，然后DispatchServlet就会调用HandlerAdapter处理器适配器，去寻找具体的controller类
>
>   然后执行controller，controller在调用业务层，获取数据然后封装到mode与view中，，再将具体的执行信息返回给HandlerAdapter，也就是ModeAndView（可理解为“我想给前端带数据并且指定这个前端是谁），再重新传递给DispatchServlet，然后DispatchServlet在调用视图解析器（View Resolver），视图解析器获取了ModeAndView中的数据，解析了ModeAndView中的视图名字，拼接视图名字，找到对应的视图，将数据渲染到这个视图上，然后视图解析器将视图名传递给DispatchServlet，DispatchServlet最后根据视图解析器解析的结果调用具体的视图，然后返回给用户

