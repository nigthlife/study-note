package com.xf.javab;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class JdbcDemo1
{

	public static void main(String[] args)
	{
		/*
		 * try { //1:添加驱动包到项目中 //2:加载驱动
		 * Class.forName("oracle.jdbc.OracleDriver");
		 * 
		 * //3:创建连接 // url: jdbc:oracle:thin:@127.0.0.1:1521:orcl // user
		 * Connection con =
		 * DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl",
		 * "wxg","888888");
		 * 
		 * //4:创建Statement对象(SQL指令) Statement st = con.createStatement();
		 * 
		 * //5:执行SQL命令 int rows = st.
		 * executeUpdate("insert into student (stuid,stuno,name,age,sex) values (10001,'J001','京东',21,'男')"
		 * );
		 * 
		 * //提示 System.out.println("执行成功：影响了" + rows + "行");
		 * 
		 * 
		 * } catch (Exception e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); }
		 * 
		 */

		//queryTest();
		try
		{
			tttt();
		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void queryTest()
	{
		Connection con = null;
		Statement st = null;
		ResultSet rs = null;
		
		// 1:添加驱动包到项目中
		// 2:加载驱动
		try
		{
			Class.forName("oracle.jdbc.OracleDriver");
			// 3:创建连接
			// url: jdbc:oracle:thin:@127.0.0.1:1521:orcl
			// user
			con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl", "wxg", "888888");

			// 4:创建Statement对象(SQL指令)
			st = con.createStatement();
			
			rs = st.executeQuery("select stuno,name,sex,age from student");

			while(rs.next())
			{
				// 处理当前行数据
				System.out.println(rs.getString(1) + rs.getString("sex") + rs.getInt("age"));
			}
			
			System.out.println("查询 成功");
			
			
			
		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally
		{
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
	
	public static void tttt() throws Exception
	{

		
			// 1:添加驱动包到项目中
			// 2:加载驱动
			Class.forName("oracle.jdbc.OracleDriver");
			
			// 3:创建连接
			//url:jdbc:oracle:thin:@127.0.0.1:1521:orcl  --固定这样写的
		    //user
			Connection con=DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl","wxg","888888");
			
		   //4:创建statment对象(执行SQL语句)
		    Statement st=con.createStatement();
		    
		   //5:执行SQL命令
		   int rows=st.executeUpdate("insert into student(stuid,stuno,name,age,sex) values (1059,'J2001','小夏',19,'女')");
		   
		   st.close();
		   
		   con.close();
		   
		   System.out.println("执行成功！影响了"+rows+"行");

		
	}

}
