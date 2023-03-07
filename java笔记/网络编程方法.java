

InetAddress类
	
	概念()
		表示互联网协议IP地址对象，封装了与该IP地址相关的所有信息。
		并提供获取信息的常用方法，

	方法()

	public static InetAddress getLocalHost();  			获得本地主机地址的对象
	public static InetAddress getByName(String host)    根据主机名称获得地址对象
	public static InetAddress[] getAllByName(String host) 获得所以相关的地址对象
	public String getHostAddress()  获得IP地址字符串
	public String getHostName()     获得IP地址主机名


	Socket编程
	Socket （套子节）是网络中的一个通信节点
	分为客户端Socket与服务器ServerSocket
	通信要求：IP地址 + 端口号

开发步骤：
	<1> 建立通信连接(会话)：
		创建ServerSocket，指定端口号
		调用accept等待客户端接入

	<2> 客户端请求服务器：
		创建Socket，指定服务器IP + 端口号
		使用输出流，发送请求数据给服务器
		使用输入流，接收响应数据给客户端（等待）

	<3> 服务器响应客户端：
		使用输入流，接收请求数据到服务器
		使用输出流，发送响应数据到客户端（等待）


总结：
	计算书网络：
		为实现资源共享和信息传递，通过通信线路连接起来的若干主机

	TCP协议：
		是一种面向连接的、可靠的、基于字节流的传输通信协议，数据大小无限制

	IP:
		分配给互联网设备的数字标签（唯一标识）

	Port:
		在通信实体上进行网络通信的程序的唯一标识

	Socket编程：
		建立连接、接收请求、发送响应