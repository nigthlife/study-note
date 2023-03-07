package com.wlp.servers;

import java.sql.Connection;
import java.sql.SQLException;

import com.wlp.BeanDao.DBUtils;



/**
 * 功能描述：事务管理类,提供获取连接，关闭自动提交事务，手动提交事务，事务回滚
 * 创建日期： 2020年11月3日 上午10:53:43
 * 创建人：武乐萍
 * com.vince.Service
 * 
 */
public class TransactionManager {
    
    protected Connection con = null;
    
    /**
     * 功能:关闭连接的自动提交事务
     */
    
    public void begin() {
	
	//获取一个连接
	con = DBUtils.getConnection();
	
	//关闭次连接的自动提交事务
	try {
	    
	    con.setAutoCommit(false);
	    
	} catch (SQLException e) {
	    e.printStackTrace();
	}
	
	
    }
    /**
     * 功能：提交事务
     */
    public void commit() {
	
	try {
	    //提交事务
	    con.commit();
	    
	    //关闭资源
	    con.close();
	    
	    //给连接赋值为空，下次使用重新获取
	    con = null;
	    
	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}
	
    }
    
    /**
     * 功能：回滚数据
     */
    public void rollback() {
	
	try {
	    //回滚数据
	    con.rollback();
	    
	    //关闭资源
	    con.close();
	    
	   //给连接赋值为空，下次使用重新获取
	    con = null;
	    
	} catch (SQLException e) {

	    e.printStackTrace();
	}
    }

}
