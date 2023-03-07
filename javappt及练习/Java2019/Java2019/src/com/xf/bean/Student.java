package com.xf.bean;

/**
 * 功能描述：
 * 创建日期：
 * 创建人 ：
 * 
 * 更新人
 * 更新日期
 * 更新内容
 *
 */
public class Student
{
    private int stuId;
    private String stuNo;
    private String name;
    private int age;
    
    /*更新开始  wxg 版本号...*/
    private String sex;
    /*更新结束 wxg  版本号...*/
    
    /**
     * 返回学生号
     * @return
     */
    public String getStuNo()
	{
		return stuNo;
	}

	public void setStuNo(String stuNo)
	{
		this.stuNo = stuNo;
	}

	public String getName()
	{
		return name;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	public int getAge()
	{
		return age;
	}

	public void setAge(int age)
	{
		this.age = age;
	}

	public String getSex()
	{
		return sex;
	}

	public void setSex(String sex)
	{
		this.sex = sex;
	}
    
	public int getStuId()
	{
		return stuId;
	}

	public void setStuId(int stuId)
	{
		this.stuId = stuId;
	}
	
	@Override
	public String toString()
	{
		return this.getStuNo() + ":" + this.getName();
	}
}
