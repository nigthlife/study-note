package com.wlp.Dao;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.wlp.Bean.task;
import com.wlp.BeanDao.Base;

/**
 * @auuter������Ƽ ���������� �������ڣ� 2020��12��5�� ����11:57:19 ������com.wlp.Dao
 * 
 */
public class taskDao extends Base {

    /**
     * ���ܲ�ѯ�������������Ϣ
     * 
     * @return ���ز�ѯ�Ľ��
     * @throws SQLException
     */
    public List<task> taskAll() throws SQLException {

	// ����list����
	List<task> task = new ArrayList<>();

	// ������ѯ�������ݵ�sql���
	String sql = "select * from task";

	// ִ��sql���
	executeSelect(sql);

	// ��ʱ����������task����
	task temp = null;

	// ��ȡ��ѯ���������
	while (rs.next()) {

	    // ����������ֵ
	    temp = new task();
	    temp.setTaskid(rs.getInt("taskid"));// ����id
	    temp.setUsId(rs.getInt("usId"));// �û�id
	    temp.setTaskName(rs.getString("taskName"));// ��������
	    temp.setTaskDetail(rs.getString("taskDetail"));// ����ϸ��
	    temp.setTaskState(rs.getShort("taskState")); // ����״̬
	    temp.setFinishedDate(rs.getString("finishedDate"));// �������
	    temp.setIsDelete(rs.getInt("isDelete"));// �Ƿ�ɾ��
	    temp.setCreateUser(rs.getInt("createUser"));// ���񴴽��û�
	    temp.setCreateDate(rs.getString("createDate"));// ���񴴽�ʱ��
	    temp.setLastUpdateUser(rs.getInt("lastUpdateUser"));// �����������û�
	    temp.setLastUpdateDate(rs.getString("lastUpdateDate")); // ����������ʱ��

	    // ��һ�����ݴ��뼯��
	    task.add(temp);

	}

	return task;

    }

    /**
     * ���ܣ������û�id��ѯ���û�����������
     * 
     * @param id
     * @return
     * @throws SQLException
     */
    public List<task> taskId(int id) throws SQLException {

	// ����list����
	List<task> task = new ArrayList<>();

	// ������ѯ�������ݵ�sql���
	String sql = "select * from task where usId=?";

	// ִ��sql���
	executeSelect(sql, id);

	// ��ʱ����������task����
	task temp = null;

	// ��ȡ��ѯ���������
	while (rs.next()) {

	    // ����������ֵ
	    temp = new task();
	    temp.setTaskid(rs.getInt("taskid"));// ����id
	    temp.setUsId(rs.getInt("usId"));// �û�id
	    temp.setTaskName(rs.getString("taskName"));// ��������
	    temp.setTaskDetail(rs.getString("taskDetail"));// ����ϸ��
	    temp.setTaskState(rs.getShort("taskState")); // ����״̬
	    temp.setFinishedDate(rs.getString("finishedDate"));// �������
	    temp.setIsDelete(rs.getInt("isDelete"));// �Ƿ�ɾ��
	    temp.setCreateUser(rs.getInt("createUser"));// ���񴴽��û�
	    temp.setCreateDate(rs.getString("createDate"));// ���񴴽�ʱ��
	    temp.setLastUpdateUser(rs.getInt("lastUpdateUser"));// �����������û�
	    temp.setLastUpdateDate(rs.getString("lastUpdateDate")); // ����������ʱ��

	    // ��һ�����ݴ��뼯��
	    task.add(temp);

	}

	return task;

    }

}
