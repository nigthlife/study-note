package com.wlp.Dao;


import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.wlp.Bean.usertable;
import com.wlp.BeanDao.Base;

/**
 * @auuter������Ƽ
 * ����������
 * �������ڣ� 2020��12��5�� ����11:57:01
 * ������com.wlp.Dao
 * 
 */
public class usertableDao extends Base{
    
    /**
     * ���ܣ���ѯ���е��û���������
     * @return ���ز�ѯ�Ľ����
     * @throws SQLException
     */
    public List<usertable> selectAll() throws SQLException {
	
	List<usertable> ustb = new ArrayList<>();
	
	// ����SQL���
	String sql = "select * form usertable";
	
	// ִ��sql���
	executeSelect(sql);
	
	// ��ʱ����
	usertable temp = null;
	
	// ��ò�ѯ�Ľ����
	while(rs.next()) {
	    
	    temp = new usertable(rs.getInt("usId"),rs.getString("usName"),rs.getString("usPaw"));
	    
	    ustb.add(temp);
	    
	}
	
	return ustb;
	
    }
    
    /**
     * ���ܣ������û����������ѯ�û�id
     * @param name
     * @param pass
     * @return
     * @throws SQLException
     */
    public int ifLonin(String name, String pass) throws SQLException {
	
	// ������������������
	int row = 0;
	
	// ����sql���
	String sql = "select usid from usertable where usname=? and usPaw=?";
	
	// ִ��sql���
	executeSelect(sql,name,pass);
	
	// ��ȡ��ѯ�Ľ��
	while(rs.next()) {
	    
	    row = rs.getInt("usid");
	}
	
	return row;
    }

}
