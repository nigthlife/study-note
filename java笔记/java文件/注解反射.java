public class Person{
	public void eat(){
		System.out.println("我喜欢吃包子....");
	}
}

/**
 * Type可作用于类上
 * METHOD可作用于方法上
 * FIELD可作用于成员变量上
 * RetentionPolicy.RUNTIME当前描述的注解会保留到class字节码文件中，并被jvm读取到
 */
@Target({ElementType.TYPE,ElementType.METHOD,ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented//描述注解是否被抽取到api文档中
@Inherited //描述注解是否被子类继承
public @interface MyAnno{
	String className();//存储注释定义的位置对象
	String ModthodName();//存储注释定义的位置对象的方法

}


@MyAnno(className = "路径",MeothodName = "方法名")
public class Test{
	public static void main(String[] args){
		//获取本类的字节码文件
		Class TestClass = Test.className();

		/**
		 * 其实内部生成了一个该类的接口的子类实现对象
		 * 
		 	public class ProImpl implements MyAnno{
		 		Public String className(){
		 			return "路径"；
		 		}
		 		public String MethodName(){
		 			return "方法名"；
		 		}
		 	}
		 *
		 */

		 //获取注解的对象(可能需要转换数据类型)
		 MyAnno myanno = TestClass.getAnnotation(MyAnno.class);

		 //调用注解对象中定义的抽象方法，并获取返回值
		 String className = myanno.ClassName();
		 String methodName = myannp.MedthodName();

		 //加载注解上的类进内存
		 Class clazz = Class.forName(className);//将获取的注解的类加载进内存
		 //创建注解上的类的对象
		 Object object = clazz.newInstacne();

		 //获取注解上的method中需要调用的方法名
		 Method method = Class.getMethod(methodName);

		 //通过invoke执行方法,invoke中传入的是此方法所在类的对象
		 method.invoke(object);

	}
}