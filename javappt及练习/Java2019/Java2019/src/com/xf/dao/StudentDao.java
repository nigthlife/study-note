package com.xf.dao;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

import com.xf.bean.Student;

public class StudentDao extends BaseDao
{

	public StudentDao()
	{
		
	}
	
	public StudentDao(Connection con)
	{
		this.con = con;
	}
	
	public void setConnection(Connection con)
	{
		this.con = con;
	}
	
    // 提供数据访问操作(CRUD操作)
	public List<Student> queryStudent(String sex) throws Exception
	{
		List<Student> stuList = new ArrayList<Student>();
		
		String sql = "select stuId,stuNo,name,age,sex from student where sex = ?";
		
		//
		executeQuery(sql,sex);
		
		Student s = null;
		
		while(rs.next())
		{
			s = new Student();
			s.setStuId(rs.getInt("stuId"));
			s.setStuNo(rs.getString("stuNo"));
			s.setName(rs.getString("name"));
			s.setAge(rs.getInt("age"));
			s.setSex(rs.getString("sex"));
			
			stuList.add(s);
		}
		
		return stuList;
	}
	
	public int deleteStudentById(int stuId)
	{
		return 0;
	}
	
	
	public int insertStudent(Student s) throws Exception
	{
		
		String sql = "insert into student (stuid,stuno,name) values(?,?,?)";

		//return executeUpdate(sql,s.getStuId(),s.getStuNo(),s.getName());

		return 0;
	}
	
	public int getNextSql() throws Exception
	{
		String sql = "select S_Student.nextVal from dual";
		
		int stuId = 0;
		
		executeQuery(sql);
		
		if(rs.next())
		{
			stuId = rs.getInt(1);
		}
		
		return stuId;
	}
	
	public int updateStudentById(Student s)
	{
		return 0;
	}
	
}
