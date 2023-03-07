package com.wlp.BeanDao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * 
 * @auuter：武乐萍
 * 功能描述：提供共有的增删改查方法 
 * 创建日期： 2020年11月9日 上午10:24:03
 * 包名：com.vince.BaseDao
 *
 */
public class Base {

    private PreparedStatement ps = null;
    protected ResultSet rs = null;
    protected Connection conn = null;

    /**
     * 实现填充传入的sql语句中的占位符
     * 
     * @param sql  	传入的sql语句
     * @param args 	可变形参
     * @throws SQLException
     * @throws Exception
     */
    public void initpreparedStatement(String sql, Object... objects) throws SQLException {

	// 判断当前是否存在连接
	if (conn == null) {
	    conn = DBUtils.getConnection();
	}

	// 预编译sql语句
	ps = conn.prepareStatement(sql);

	// 循环填充占位符
	for (int i = 0; i < objects.length; i++) {

	    ps.setObject(i + 1, objects[i]);
	    
	}

    }

    
    /**
     * 功能：实现对表的添、删、改操作
     * @param sql	需要执行的sql语句
     * @param objects   填充占位符参数个数
     * @return		执行sql语句并返回影响数据行数
     * @throws SQLException
     */
    public int executeUpdate(String sql, Object... objects) throws SQLException {
	
	// 调用填充占位符方法
	initpreparedStatement(sql, objects);

	//执行sql语句并返回影响数据行数
	return ps.executeUpdate();
    }

   
    /**
     * 功能：实现对表的查询操作
     * @param sql		需要执行的sql语句	
     * @param objects		填充占位符参数个数
     * @throws SQLException
     */
    public void executeSelect(String sql, Object... objects) throws SQLException {

	// 调用填充占位符方法
	initpreparedStatement(sql, objects);

	//执行结果接收结果集
	rs = ps.executeQuery();
    }

    /**
     * 功能：关闭资源
     */
    public void close() {

	//调用工具类中的关闭资源方法
	DBUtils.close(conn, ps, rs);
	
    }

}
