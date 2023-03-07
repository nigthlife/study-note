package com.xf.javab;

import java.util.List;

import com.xf.bean.Student;
import com.xf.dao.StudentDao;

public class Test1
{

	public static void main(String[] args) throws Exception
	{
		/*test();
		test(1);
		test(1,2);
		test(1,2,3,4,5);*/
		
		List<Student> stus = new StudentDao().queryStudent("ÄÐ");
		
		
		for (Student s : stus)
		{
			System.out.println(s);
		}
	}
	
	public static void test(int ... nums)
	{
		// Êý×é
		for (int i = 0; i < nums.length; i++)
		{
			System.out.println(nums[i]);
		}
		
		System.out.println();
	}

}
