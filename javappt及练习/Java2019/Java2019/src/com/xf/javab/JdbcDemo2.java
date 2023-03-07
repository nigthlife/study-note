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
		// PreparedStatement֪ʶ
		// queryTest();
		queryTestPer();
	}

	public static void queryTest()
	{
		Scanner sc = new Scanner(System.in);
		
		Connection con = null;
		Statement st = null;
		ResultSet rs = null;

		System.out.println("������Ҫ��ѯ��ѧ������:");
		String stuName = sc.nextLine();
		
		// 1:�������������Ŀ��
		// 2:��������
		try
		{
			Class.forName("oracle.jdbc.OracleDriver");
			// 3:��������
			// url: jdbc:oracle:thin:@127.0.0.1:1521:orcl
			// user
			con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl", "wxg", "888888");

			// 4:����Statement����(SQLָ��)
			st = con.createStatement();

			rs = st.executeQuery("select stuno,name,sex,age from student where name = '" +  stuName + "'");

			while (rs.next())
			{
				// ����ǰ������
				System.out.println(rs.getString(1) + rs.getString("name") + rs.getInt("age"));
			}

			System.out.println("��ѯ �ɹ�");

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

		System.out.println("������Ҫ��ѯ��ѧ������:");
		String stuName = sc.nextLine();
		
		// 1:�������������Ŀ��
		// 2:��������
		try
		{
			Class.forName("oracle.jdbc.OracleDriver");
			// 3:��������
			// url: jdbc:oracle:thin:@127.0.0.1:1521:orcl
			// user
			con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl", "wxg", "888888");

			String sql = "select stuno,name,sex,age from student where name = ?";
			
			// 4:����Statement����(SQLָ��)
			ps = con.prepareStatement(sql);
			// ���ö�Ӧ������ֵ	
		    ps.setString(1, stuName);

			rs = ps.executeQuery();

			while (rs.next())
			{
				// ����ǰ������
				System.out.println(rs.getString(1) + rs.getString("name") + rs.getInt("age"));
			}

			System.out.println("��ѯ �ɹ�");

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