package com.xf.service;

import com.xf.bean.Student;
import com.xf.dao.StudentDao;

public class StudentService extends TransactionManager
{
	// StudentDao
	// CourseDao
	// SCDao
	StudentDao studentDao = new StudentDao();
	//CourseDao courseDao = new CourseDao();
	//SCDao scDao = new SCDao();
	public void saveStudent(Student stu)
	{
		try
		{
			begin();
			
			studentDao.setConnection(con);
			//courseDao.setConnection(con);
			//scDao.setConnection(con);
			 
			// �ȵ��ò�ѯ��ǰ���Ӧ����һ�����кţ� StudentDao.getNextSql() int��
			int stuId = studentDao.getNextSql();
			stu.setStuId(stuId);
			studentDao.insertStudent(stu);
			
			// courseDao.selectAll() List<Course>
			
			/* for() 
			 * SC = new SC()
			 * scId
			 * cid
			 * score = 0
			 * stuid:
			scDao.insert(SC sc)
		    */ 
			
			commit();

		} catch (Exception e)
		{
			rollback();
			e.printStackTrace();
		}
	}

}
