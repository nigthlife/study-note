package com.qf.poly_1;

/**
 * 动物类(父类)
 * @author wgy
 *
 */
public class Animal {
	//品种
	 String breed;
	//年龄
	 int age;
	//性别
	 String sex;
	
	//吃
	public void eat() {
		System.out.println("吃.......");
	}
	//睡
	public void sleep() {
		System.out.println("睡........");
	}
}
