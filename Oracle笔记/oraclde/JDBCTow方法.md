# 目录





[java中JDBC使用](https://blog.csdn.net/qq_22172133/article/details/81266048)

## 1.JDBC方法

##### 1.1加载配置文件中的驱动两种方式

```java 
public static String url null;
public static String user null;
public static String password null;

-- <第一种：获取类加载器>
  -- <使用类加载器获取 <src> 目录下的配置文件,返回一个字节输入流>
  InputStream is = ClassLoder.getSystemClassLoder.getResourceAsStream(配置文件名);
  -- <创建一个配置文件类>	
	Preperties ps = new Preperties();
	-- <通过返回的字节输入流获取配置文件中的信息>
    url = is.getPreperty(key);  -- 获取文件中的url
		user = is.getPreperty(key);	-- 获取文件中的用户名
		password = is.getPreperty(key);	-- 获取文件中的用户名密码
    
    -- 利用静态代码块加载驱动，静态代码块中默认创建了一个Driver对象
    -- 使用DriverManager.registerDriver(new Driver)来注册驱动,而Driver
		Class.forName(is.getPreperty(key));	

-- <第二种：获取类加载器方法>
  -- <使用类加载器获取本包目录下的配置文件信息>
  -- <创建一个配置文件对象>
  	Preperties ps4 = new Preperties();
	-- 使用Preperties对象中的load方法获取本类加载器
    ps4.load(本类类名.Class.getResourceAsStream("配置文件名"));

	-- <通过文件类对象获取文件中的信息>
		url = p.getProperty("url");
		user = p.getProperty("user");
		pwd = p.getProperty("pwd");
	-- 通过静态代码块加载驱动
		Class.forName(p.getProperty("driver"));
		
```

> 说明：使用配置文件的方式保存配置信息，在代码中加载配置文件
>
> **使用配置文件的好处：**
>
> ①**实现了代码和数据的分离**，如果需要修改配置信息，直接在配置文件中修改，不需要深入代码
> ②如果修改了配置信息，省去重新编译的过程。

##### 1.2Oracle驱动名称

> **oracle.jdbc.driver.OracleDriver**

##### 1.3url概念

> JDBC URL 用于标识一个被注册的驱动程序，驱动程序管理器通过这个 URL 选择正确的驱动程序，从而建立到数据库的连接。
>
> JDBC URL的标准由**三部分组成**，各部分间用冒号分隔。 
>
> - **jdbc:子协议:子名称**
> - **协议**：JDBC URL中的协议总是jdbc 
> - **子协议**：子协议用于标识一个数据库驱动程序
> - **子名称**：一种标识数据库的方法。
>   - ​		子名称可以依不同的子协议而变化，用子名称的目的是为了**定位数据库**提供足够的信息。
>     - ​	包含**主机名**(对应服务端的ip地址)**，端口号，数据库名**



##2.创建数据库连接

#### 1.[Connection](#目录)

```java
public class demp{
  public static void main(String[] args){
    try{
      //1.添加驱动包到项目中
      //2.加载驱动
      Class.forName("oracle.jdbc.OracleDriver");
      //3.创建连接
      Connection con = DriverManager.getConnection
        ("jdbc.oracle:thin@127.0.0.1:1521:orcl","java2019","888888");
      //4.创建Statement对象
      Statement st = con.createStatement();
      
      //执行更新命令
      //有一个返回值，影响的行数
      int row = st.executeUpdate("sql语句");
      
      //执行查询命令
      //返回一个ResultSet对象
      ResultSet rs = st.executeQuery("sql语句");
      //循环迭代ResultSet对象
      while(rs.next()){
        //根据字段的数据类型输出语句
        System.out.println(rs.getString(1));
      }
      (
    }catch(Exception e){
      e.printStackTrace();
    }finally{ // 关闭资源
			try
			{
				if(rs != null)
				{
				    rs.close();
				}
				
			} catch (SQLException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			try
			{
				if(st != null)
				{
				    st.close();
				}
			} catch (SQLException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			try
			{
				if(con != null)
				{
				    con.close();
				}
				
			} catch (SQLException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
  }
}
```

#### 2.[preperedStatement](#目录)

> PreparedStatement 可对SQL进行预编译，从而提高数据库的执行效率。

> Statement会使数据库频繁编译SQL，可能造成数据库缓冲区溢出