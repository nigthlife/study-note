# 目录





[java中JDBC使用](https://blog.csdn.net/qq_22172133/article/details/81266048)



#### 事务的四大特性

-   **原子性：**事务中的所有操作是一个整体，或者整体执行成功，亦或整体执行失败
-   **一致性：**事务执行后，数据库状态与其他业务规则保持一致
-   **隔离性：**在并发操作中，每个并发中的事务的执行不会相互干扰
-   **持久性：**事务一旦提交成功，事务中的所有数据被持久化到数据库中





##创建数据库连接

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