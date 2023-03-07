package com.xf.javab;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

public class JdbcDemo2
{
	public static void main(String[] args)
	{
		// PreparedStatement知识
		// queryTest();
		queryTestPer();
	}

	public static void queryTest()
	{
		Scanner sc = new Scanner(System.in);
		
		Connection con = null;
		Statement st = null;
		ResultSet rs = null;

		System.out.println("请输入要查询的学生姓名:");
		String stuName = sc.nextLine();
		
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

			rs = st.executeQuery("select stuno,name,sex,age from student where name = '" +  stuName + "'");

			while (rs.next())
			{
				// 处理当前行数据
				System.out.println(rs.getString(1) + rs.getString("name") + rs.getInt("age"));
			}

			System.out.println("查询 成功");

		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally
		{
			try
			{
				if (rs != null)
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
				if (st != null)
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
				if (con != null)
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

	public static void queryTestPer()
	{
		Scanner sc = new Scanner(System.in);
		
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;

		System.out.println("请输入要查询的学生姓名:");
		String stuName = sc.nextLine();
		
		// 1:添加驱动包到项目中
		// 2:加载驱动
		try
		{
			Class.forName("oracle.jdbc.OracleDriver");
			// 3:创建连接
			// url: jdbc:oracle:thin:@127.0.0.1:1521:orcl
			// user
			con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl", "wxg", "888888");

			String sql = "select stuno,name,sex,age from student where name = ?";
			
			// 4:创建Statement对象(SQL指令)
			ps = con.prepareStatement(sql);
			// 设置对应参数的值	
		    ps.setString(1, stuName);

			rs = ps.executeQuery();

			while (rs.next())
			{
				// 处理当前行数据
				System.out.println(rs.getString(1) + rs.getString("name") + rs.getInt("age"));
			}

			System.out.println("查询 成功");

		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally
		{
			try
			{
				if (rs != null)
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
				if (ps != null)
				{
					ps.close();
				}
			} catch (SQLException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			try
			{
				if (con != null)
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