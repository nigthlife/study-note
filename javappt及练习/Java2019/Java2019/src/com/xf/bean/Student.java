package com.xf.bean;

/**
 * ����������
 * �������ڣ�
 * ������ ��
 * 
 * ������
 * ��������
 * ��������
 *
 */
public class Student
{
    private int stuId;
    private String stuNo;
    private String name;
    private int age;
    
    /*���¿�ʼ  wxg �汾��...*/
    private String sex;
    /*���½��� wxg  �汾��...*/
    
    /**
     * ����ѧ����
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
