package com.xf.javab;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

public class JdbcDemo3
{

	public static void main(String[] args)
	{
		// 事务
		// 1:Connection: 更新数据是自动提交，处理事务时，需要把连接对象的自动提交设置为“不自动”
		transactionDemo();
	}

	public static void transactionDemo()
	{
		Connection con = null;
		PreparedStatement ps = null;

		try
		{
			// 1:添加驱动包到项目中
			// 2:加载驱动
			Class.forName("oracle.jdbc.OracleDriver");
			// 3:创建连接
			// url: jdbc:oracle:thin:@127.0.0.1:1521:orcl
			// user
			con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl", "scott", "888888");

			// 设置事务不要自动提交
			con.setAutoCommit(false);
			
			// 4:创建Statement对象(SQL指令)
			String sql = "update account set money = money + 10000 where userId = 2";
			ps = con.prepareStatement(sql);
			ps.executeUpdate();
            ps.close();
			
            System.out.println(1/0);
            
			sql = "update account set money = money - 10000 where userId = 3";
			ps = con.prepareStatement(sql);
			ps.executeUpdate();

			// 提交事务
			con.commit();
			System.out.println("转账 成功");

		} catch (Exception e)
		{
			try
			{
				con.rollback();
				
			} catch (SQLException e1)
			{
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			e.printStackTrace();
		} finally
		{
			
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