package com.wlp.servers;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.wlp.Bean.task;
import com.wlp.Dao.taskDao;
import com.wlp.Dao.usertableDao;

/**
 * @auuter������Ƽ ���������� �������ڣ� 2020��12��6�� ����12:02:57 ������com.wlp.servers
 * 
 */
public class server extends TransactionManager {

    // �����û���dao�����
    usertableDao user = new usertableDao();

    // ���������dao�����
    taskDao task = new taskDao();

    /**
     * ���ܣ���ѯ���е�������Ϣ
     * 
     * @return
     */
    public List<task> selectTaskAll() {

	List<task> taskAll = new ArrayList<>();

	try {

	    // ���ò�ѯ���������ز�ѯ�Ľ����
	    taskAll = task.taskAll();

	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

	// ���ز�ѯ������
	return taskAll;

    }

    /**
     * ���ܣ������û����������ѯ�û�id��
     * 
     * @param name �û���
     * @param pass ����
     * @return ����id��
     */
    public int selectUserId(String name, String pass) {

	// ��ʱ����
	int id = 0;

	try {

	    // ִ��ѯ�����������û�id
	    id = user.ifLonin(name, pass);

	} catch (SQLException e) {

	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

	// ����id��
	return id;

    }

    public List<task> selectOne(int id) {

	List<task> taskone = new ArrayList<>();

	try {

	    // ���ò�ѯ���������ز�ѯ�Ľ����
	    taskone = task.taskId(id);

	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

	// ���ز�ѯ������
	return taskone;

    }

}
