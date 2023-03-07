package com.wlp.BeanDao;


import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;



/**
 * 
 * @auuter������Ƽ
 * �����������ṩ������������ȡ���ӵķ���
 * �������ڣ� 2020��11��9�� ����10:26:04
 * ������com.vince.BaseDao
 *
 */
public class DBUtils {

    private static String url = null; 		// �ṩurl��ָ���������������
    private static String user = null; 		// "wlp";
    private static String password = null; 	// 888888

    static {

	try {

	    //���һ��Properties����
	    Properties ties = new Properties();
	    
	    //ʹ�ñ�������������ر����µ������ļ�
	    ties.load(DBUtils.class.getResourceAsStream("dbconfig.properties"));

	    //��ȡ�����ļ���Ϣ
	    url = ties.getProperty("url");
	   
	    user = ties.getProperty("user");
	    
	    password = ties.getProperty("password");
	   
	    
	    //��������
	    Class.forName(ties.getProperty("driver"));

	} catch (IOException e) {
	    
	    e.printStackTrace();
	    
	} catch (ClassNotFoundException e) {
	    
	    e.printStackTrace();
	}

    }


    /**
     * ���ܣ��ṩһ��ͳһ�Ļ�ȡ���ӷ���
     * @return
     */
    public static Connection getConnection() {
	
	
	Connection con = null;

	try {
	    //��ȡ����
	    
	    con =  DriverManager.getConnection(url, user, password);
	    
	} catch (SQLException e) {

	    e.printStackTrace();
	}
	
	//����һ������
	return con;
    }

    /**
     * 	�ر���Դ
     * @param con
     * @param ps
     * @param rs
     */
    public static void close(Connection con, PreparedStatement ps, ResultSet rs) {

	try {
	    
	    //�жϽ�����Ƿ�Ϊ��
	    if (rs != null) {
		
		//�ر���Դ
		rs.close();
	    }

	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}

	try {
	    
	    //�ж�Ԥ����sql�������Ƿ�Ϊ��
	    if (ps != null) {
		
		//�ر���Դ
		ps.close();
	    }
	    
	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}

	try {
	    
	    //�ж������Ƿ�Ϊ��
	    if (con != null) {
		
		//�ر���Դ
		con.close();
	    }

	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}

    }
    

}
