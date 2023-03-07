package com.xf.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class BaseDao
{
	protected Connection con = null;
	private PreparedStatement ps = null;
	protected ResultSet rs = null;
	
	private void initPreparedStatement(String sql, Object ... objs) throws Exception
	{
		if(con == null)
		{
		    con = DbUtils.getConnection();
		}
	    
	    ps = con.prepareStatement(sql);
		
	    for (int i = 0; i < objs.length; i++)
		{
			ps.setObject(i+1, objs[i]);
		}
	}
	
	public int executeUpdate(String sql, Object ... objs) throws Exception
	{
		initPreparedStatement(sql,objs);
	
		return ps.executeUpdate();
	}
	
	public void executeQuery(String sql, Object ... objs) throws Exception
	{
		initPreparedStatement(sql,objs);
		
		rs = ps.executeQuery();
		
	}
	
	public void close()
	{
		DbUtils.close(rs, con, ps);
	}
}
