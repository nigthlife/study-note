package com.wlp.servers;

import java.sql.Connection;
import java.sql.SQLException;

import com.wlp.BeanDao.DBUtils;



/**
 * �������������������,�ṩ��ȡ���ӣ��ر��Զ��ύ�����ֶ��ύ��������ع�
 * �������ڣ� 2020��11��3�� ����10:53:43
 * �����ˣ�����Ƽ
 * com.vince.Service
 * 
 */
public class TransactionManager {
    
    protected Connection con = null;
    
    /**
     * ����:�ر����ӵ��Զ��ύ����
     */
    
    public void begin() {
	
	//��ȡһ������
	con = DBUtils.getConnection();
	
	//�رմ����ӵ��Զ��ύ����
	try {
	    
	    con.setAutoCommit(false);
	    
	} catch (SQLException e) {
	    e.printStackTrace();
	}
	
	
    }
    /**
     * ���ܣ��ύ����
     */
    public void commit() {
	
	try {
	    //�ύ����
	    con.commit();
	    
	    //�ر���Դ
	    con.close();
	    
	    //�����Ӹ�ֵΪ�գ��´�ʹ�����»�ȡ
	    con = null;
	    
	} catch (SQLException e) {
	    
	    e.printStackTrace();
	}
	
    }
    
    /**
     * ���ܣ��ع�����
     */
    public void rollback() {
	
	try {
	    //�ع�����
	    con.rollback();
	    
	    //�ر���Դ
	    con.close();
	    
	   //�����Ӹ�ֵΪ�գ��´�ʹ�����»�ȡ
	    con = null;
	    
	} catch (SQLException e) {

	    e.printStackTrace();
	}
    }

}
