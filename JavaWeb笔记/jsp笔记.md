> **jSTL**标签库 全称 JSP Standard Tag Library  JSP 标准标签库
>
> 是一个不断完事的开放源代码的JSP标签库
>
> **通过taglib指令引入标签库**
>
> **prefix标签的前缀  uri标签库的类型**	

> <% 
>
> ​	一般可以在开头写上Attribute语句以减少request的单词量
>
> ​	pageContext.setAttribute("req","request")
>
> %
>
> request.getScheme()	它可以获取请求的协议
>
> $(pageContext.request.scheme ) el表达式方法就是去除get
>
> request.getServerName()	获取请求的服务器ip或域名
>
> request.getServerPort()	获取请求的服务器端口号
>
> request.getContextPath()	获取当前工程路径
>
> request.getMethod()	获取请求的方式（get或者post请求）
>
> request.getRemoteHost()	获取客户端的id地址
>
> request.getId()	获取会话的唯一标识
>
> $(pageContext.session.id ) 

> 获取Cooike的名称：$(cookie.JSESSIONID.name)
>
> 获取Cooike的值：$(cookie.JSESSIONID.value)

