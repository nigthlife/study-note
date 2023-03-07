package com.wlp.Dao;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.wlp.Bean.task;
import com.wlp.BeanDao.Base;

/**
 * @auuter：武乐萍 功能描述： 创建日期： 2020年12月5日 下午11:57:19 包名：com.wlp.Dao
 * 
 */
public class taskDao extends Base {

    /**
     * 功能查询任务表中所有信息
     * 
     * @return 返回查询的结果
     * @throws SQLException
     */
    public List<task> taskAll() throws SQLException {

	// 创建list集合
	List<task> task = new ArrayList<>();

	// 创建查询所以数据的sql语句
	String sql = "select * from task";

	// 执行sql语句
	executeSelect(sql);

	// 临时变量，保存task对象
	task temp = null;

	// 获取查询结果集数据
	while (rs.next()) {

	    // 创建对象并设值
	    temp = new task();
	    temp.setTaskid(rs.getInt("taskid"));// 任务id
	    temp.setUsId(rs.getInt("usId"));// 用户id
	    temp.setTaskName(rs.getString("taskName"));// 任务名称
	    temp.setTaskDetail(rs.getString("taskDetail"));// 任务细节
	    temp.setTaskState(rs.getShort("taskState")); // 任务状态
	    temp.setFinishedDate(rs.getString("finishedDate"));// 完成日期
	    temp.setIsDelete(rs.getInt("isDelete"));// 是否删除
	    temp.setCreateUser(rs.getInt("createUser"));// 任务创建用户
	    temp.setCreateDate(rs.getString("createDate"));// 任务创建时间
	    temp.setLastUpdateUser(rs.getInt("lastUpdateUser"));// 任务最后更新用户
	    temp.setLastUpdateDate(rs.getString("lastUpdateDate")); // 任务最后更新时间

	    // 将一行数据存入集合
	    task.add(temp);

	}

	return task;

    }

    /**
     * 功能：根据用户id查询该用户的所有任务
     * 
     * @param id
     * @return
     * @throws SQLException
     */
    public List<task> taskId(int id) throws SQLException {

	// 创建list集合
	List<task> task = new ArrayList<>();

	// 创建查询所以数据的sql语句
	String sql = "select * from task where usId=?";

	// 执行sql语句
	executeSelect(sql, id);

	// 临时变量，保存task对象
	task temp = null;

	// 获取查询结果集数据
	while (rs.next()) {

	    // 创建对象并设值
	    temp = new task();
	    temp.setTaskid(rs.getInt("taskid"));// 任务id
	    temp.setUsId(rs.getInt("usId"));// 用户id
	    temp.setTaskName(rs.getString("taskName"));// 任务名称
	    temp.setTaskDetail(rs.getString("taskDetail"));// 任务细节
	    temp.setTaskState(rs.getShort("taskState")); // 任务状态
	    temp.setFinishedDate(rs.getString("finishedDate"));// 完成日期
	    temp.setIsDelete(rs.getInt("isDelete"));// 是否删除
	    temp.setCreateUser(rs.getInt("createUser"));// 任务创建用户
	    temp.setCreateDate(rs.getString("createDate"));// 任务创建时间
	    temp.setLastUpdateUser(rs.getInt("lastUpdateUser"));// 任务最后更新用户
	    temp.setLastUpdateDate(rs.getString("lastUpdateDate")); // 任务最后更新时间

	    // 将一行数据存入集合
	    task.add(temp);

	}

	return task;

    }

}
