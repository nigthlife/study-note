package com.qf.chap17_5;
/**
 * 创建注解类型  @interface
 * @author wgy
 *
 */
public @interface MyAnnotation {
	//属性(类似方法)
	String name() default "张三";
	int age() default 20;
	
}
