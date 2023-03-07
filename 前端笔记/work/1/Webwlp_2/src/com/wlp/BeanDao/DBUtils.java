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
 * @auuter：武乐萍
 * 功能描述：提供加载驱动、获取连接的方法
 * 创建日期： 2020年11月9日 上午10:26:04
 * 包名：com.vince.BaseDao
 *
 */
public class DBUtils {

    private static String url = null; 		// 提供url，指明具体操作的数据
    private static String user = null; 		// "wlp";
    private static String password = null; 	// 888888

    static {

	try {

	    //获得一个Properties对象
	    Properties ties = new Properties();
	    
	    //使用本类类加载器加载本包下的配置文件
	    ties.load(DBUtils.class.getResourceAsStream("dbconfig.properties"));

	    //读取配置文件信息
	    url = ties.getProperty("url");
	   
	    user = ties.getProperty("user");
	    
	    password = ties.getProperty("password");
	   
	    
	    //加载驱动
	    Class.forName(ties.getProperty("driver"));

	} catch (IOException e) {
	    
	    e.printStackTrace();
	    
	} catch (ClassNotFoundException e) {
	    
	    e.printStackTrace();
	}

    }


    /**
     * 功能：提供一个统一的获取连接方法
     * @return
     */
    public static Connection getConnection() {
	
	
	Connection con = null;

	try {
	    //获取连接
	    
	    con =  DriverManager.getConnection(url, user, password);
	    
	} catch (SQLException e) {

	    e.printStackTrace();
	}
	
	//返回一个连接
	return con;
    }

    /**
     * 	关闭资源
     * @param con
     * @param ps
     * @param rs
     */
    public static void close(Connection con, PreparedStatement ps, ResultSet rs) {

	try {
	    
	    //判断结果集是否不为空
	    if (rs != null) {
		
		//关闭资源
		rs.close();
	    }

	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}

	try {
	    
	    //判断预编译sql语句对象是否不为空
	    if (ps != null) {
		
		//关闭资源
		ps.close();
	    }
	    
	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}

	try {
	    
	    //判断连接是否不为空
	    if (con != null) {
		
		//关闭资源
		con.close();
	    }

	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}

    }
    

}
