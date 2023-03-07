package com.xf.ui;

import java.util.Scanner;

import com.xf.bean.Student;

public class StudentController
{
    public static void main(String[] args)
    {
    	// 收集学生数据
    	Scanner sc = new Scanner(System.in);
    	
    	Student stu = new Student();
    	stu.setStuNo("S102");
    	stu.setName("良王子");
    	stu.setSex("男");
    	stu.setAge(21);
    	
    	
    	
    }
}
