package com.xf.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

public class DbUtils
{
	//
	public static String url = null;// "jdbc:oracle:thin:@127.0.0.1:1521:orcl";
	public static String user = null; // "wxg";
	public static String pwd = null; // "888888";

	static
	{
		try
		{
			Properties p = new Properties();

			p.load(StudentDao.class.getResourceAsStream("dbconfig.properties"));

			url = p.getProperty("url");
			user = p.getProperty("user");
			pwd = p.getProperty("pwd");
			Class.forName(p.getProperty("driver"));

		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static Connection getConnection()
	{
		Connection con = null;
		try
		{
			con = DriverManager.getConnection(url, user, pwd);

		} catch (SQLException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return con;
	}

	public static void close(ResultSet rs, Connection con, PreparedStatement ps)
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
