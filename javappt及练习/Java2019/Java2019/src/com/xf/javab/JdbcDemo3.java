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
		// ����
		// 1:Connection: �����������Զ��ύ����������ʱ����Ҫ�����Ӷ�����Զ��ύ����Ϊ�����Զ���
		transactionDemo();
	}

	public static void transactionDemo()
	{
		Connection con = null;
		PreparedStatement ps = null;

		try
		{
			// 1:�������������Ŀ��
			// 2:��������
			Class.forName("oracle.jdbc.OracleDriver");
			// 3:��������
			// url: jdbc:oracle:thin:@127.0.0.1:1521:orcl
			// user
			con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl", "scott", "888888");

			// ��������Ҫ�Զ��ύ
			con.setAutoCommit(false);
			
			// 4:����Statement����(SQLָ��)
			String sql = "update account set money = money + 10000 where userId = 2";
			ps = con.prepareStatement(sql);
			ps.executeUpdate();
            ps.close();
			
            System.out.println(1/0);
            
			sql = "update account set money = money - 10000 where userId = 3";
			ps = con.prepareStatement(sql);
			ps.executeUpdate();

			// �ύ����
			con.commit();
			System.out.println("ת�� �ɹ�");

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