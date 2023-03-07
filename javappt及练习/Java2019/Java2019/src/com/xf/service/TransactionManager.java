package com.xf.service;

import java.sql.Connection;
import java.sql.SQLException;

import com.xf.dao.DbUtils;

public class TransactionManager
{
    protected Connection con = null;
    
    public void begin()
    {
    	con = DbUtils.getConnection();
    	
    	try
		{
			con.setAutoCommit(false);
			
		} catch (SQLException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void commit()
    {
    	try
		{
    		con.commit();
			con.close();
			con = null;
		} catch (SQLException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void rollback()
    {
    	try
		{
			con.rollback();
			con.close();
			con = null;
			
		} catch (SQLException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
}
