package com.wlp.BeanDao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * 
 * @auuter������Ƽ
 * �����������ṩ���е���ɾ�Ĳ鷽�� 
 * �������ڣ� 2020��11��9�� ����10:24:03
 * ������com.vince.BaseDao
 *
 */
public class Base {

    private PreparedStatement ps = null;
    protected ResultSet rs = null;
    protected Connection conn = null;

    /**
     * ʵ����䴫���sql����е�ռλ��
     * 
     * @param sql  	�����sql���
     * @param args 	�ɱ��β�
     * @throws SQLException
     * @throws Exception
     */
    public void initpreparedStatement(String sql, Object... objects) throws SQLException {

	// �жϵ�ǰ�Ƿ��������
	if (conn == null) {
	    conn = DBUtils.getConnection();
	}

	// Ԥ����sql���
	ps = conn.prepareStatement(sql);

	// ѭ�����ռλ��
	for (int i = 0; i < objects.length; i++) {

	    ps.setObject(i + 1, objects[i]);
	    
	}

    }

    
    /**
     * ���ܣ�ʵ�ֶԱ����ɾ���Ĳ���
     * @param sql	��Ҫִ�е�sql���
     * @param objects   ���ռλ����������
     * @return		ִ��sql��䲢����Ӱ����������
     * @throws SQLException
     */
    public int executeUpdate(String sql, Object... objects) throws SQLException {
	
	// �������ռλ������
	initpreparedStatement(sql, objects);

	//ִ��sql��䲢����Ӱ����������
	return ps.executeUpdate();
    }

   
    /**
     * ���ܣ�ʵ�ֶԱ�Ĳ�ѯ����
     * @param sql		��Ҫִ�е�sql���	
     * @param objects		���ռλ����������
     * @throws SQLException
     */
    public void executeSelect(String sql, Object... objects) throws SQLException {

	// �������ռλ������
	initpreparedStatement(sql, objects);

	//ִ�н�����ս����
	rs = ps.executeQuery();
    }

    /**
     * ���ܣ��ر���Դ
     */
    public void close() {

	//���ù������еĹر���Դ����
	DBUtils.close(conn, ps, rs);
	
    }

}
