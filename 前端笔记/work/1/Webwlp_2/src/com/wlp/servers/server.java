package com.wlp.servers;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.wlp.Bean.task;
import com.wlp.Dao.taskDao;
import com.wlp.Dao.usertableDao;

/**
 * @auuter：武乐萍 功能描述： 创建日期： 2020年12月6日 上午12:02:57 包名：com.wlp.servers
 * 
 */
public class server extends TransactionManager {

    // 创建用户表dao类对象
    usertableDao user = new usertableDao();

    // 创建任务表dao类对象
    taskDao task = new taskDao();

    /**
     * 功能：查询所有的任务信息
     * 
     * @return
     */
    public List<task> selectTaskAll() {

	List<task> taskAll = new ArrayList<>();

	try {

	    // 调用查询方法，返回查询的结果集
	    taskAll = task.taskAll();

	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

	// 返回查询的数据
	return taskAll;

    }

    /**
     * 功能：根据用户名和密码查询用户id号
     * 
     * @param name 用户名
     * @param pass 密码
     * @return 返回id号
     */
    public int selectUserId(String name, String pass) {

	// 临时变量
	int id = 0;

	try {

	    // 执查询方法并返回用户id
	    id = user.ifLonin(name, pass);

	} catch (SQLException e) {

	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

	// 返回id号
	return id;

    }

    public List<task> selectOne(int id) {

	List<task> taskone = new ArrayList<>();

	try {

	    // 调用查询方法，返回查询的结果集
	    taskone = task.taskId(id);

	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}

	// 返回查询的数据
	return taskone;

    }

}
