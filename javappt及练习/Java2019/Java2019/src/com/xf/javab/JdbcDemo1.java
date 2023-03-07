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
		 * try { //1:�������������Ŀ�� //2:��������
		 * Class.forName("oracle.jdbc.OracleDriver");
		 * 
		 * //3:�������� // url: jdbc:oracle:thin:@127.0.0.1:1521:orcl // user
		 * Connection con =
		 * DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl",
		 * "wxg","888888");
		 * 
		 * //4:����Statement����(SQLָ��) Statement st = con.createStatement();
		 * 
		 * //5:ִ��SQL���� int rows = st.
		 * executeUpdate("insert into student (stuid,stuno,name,age,sex) values (10001,'J001','����',21,'��')"
		 * );
		 * 
		 * //��ʾ System.out.println("ִ�гɹ���Ӱ����" + rows + "��");
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
			
			rs = st.executeQuery("select stuno,name,sex,age from student");

			while(rs.next())
			{
				// ����ǰ������
				System.out.println(rs.getString(1) + rs.getString("sex") + rs.getInt("age"));
			}
			
			System.out.println("��ѯ �ɹ�");
			
			
			
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

		
			// 1:�������������Ŀ��
			// 2:��������
			Class.forName("oracle.jdbc.OracleDriver");
			
			// 3:��������
			//url:jdbc:oracle:thin:@127.0.0.1:1521:orcl  --�̶�����д��
		    //user
			Connection con=DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl","wxg","888888");
			
		   //4:����statment����(ִ��SQL���)
		    Statement st=con.createStatement();
		    
		   //5:ִ��SQL����
		   int rows=st.executeUpdate("insert into student(stuid,stuno,name,age,sex) values (1059,'J2001','С��',19,'Ů')");
		   
		   st.close();
		   
		   con.close();
		   
		   System.out.println("ִ�гɹ���Ӱ����"+rows+"��");

		
	}

}
