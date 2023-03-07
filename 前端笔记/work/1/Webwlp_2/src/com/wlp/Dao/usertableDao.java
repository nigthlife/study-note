package com.wlp.Dao;


import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.wlp.Bean.usertable;
import com.wlp.BeanDao.Base;

/**
 * @auuter：武乐萍
 * 功能描述：
 * 创建日期： 2020年12月5日 下午11:57:01
 * 包名：com.wlp.Dao
 * 
 */
public class usertableDao extends Base{
    
    /**
     * 功能：查询所有的用户名和密码
     * @return 返回查询的结果集
     * @throws SQLException
     */
    public List<usertable> selectAll() throws SQLException {
	
	List<usertable> ustb = new ArrayList<>();
	
	// 创建SQL语句
	String sql = "select * form usertable";
	
	// 执行sql语句
	executeSelect(sql);
	
	// 临时变量
	usertable temp = null;
	
	// 获得查询的结果集
	while(rs.next()) {
	    
	    temp = new usertable(rs.getInt("usId"),rs.getString("usName"),rs.getString("usPaw"));
	    
	    ustb.add(temp);
	    
	}
	
	return ustb;
	
    }
    
    /**
     * 功能：根据用户名和密码查询用户id
     * @param name
     * @param pass
     * @return
     * @throws SQLException
     */
    public int ifLonin(String name, String pass) throws SQLException {
	
	// 符合条件的数据数量
	int row = 0;
	
	// 创建sql语句
	String sql = "select usid from usertable where usname=? and usPaw=?";
	
	// 执行sql语句
	executeSelect(sql,name,pass);
	
	// 获取查询的结果
	while(rs.next()) {
	    
	    row = rs.getInt("usid");
	}
	
	return row;
    }

}
