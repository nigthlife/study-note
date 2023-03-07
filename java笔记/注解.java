类泛型
	public class 类名<泛型>{} 
	class 类名<泛型>
类泛型
	public class 类名<泛型>{
		泛型 a;
		泛型 b;
		public 类名(泛型 b){}
	} 
接口泛型
	interface 接口名称<泛型>{}

方法泛型
	public <T(声明这是一个泛型方法)> T(返回值类型为类型T) 方法名称(<T> c){}
	（在定义泛型方法时，必须在返回值前边加一个<T>,来声明这是一个泛型方法，持有一个泛型T,然后才可以用泛型T作为方法的返回值）


	List<emp> list = new ArrayList<emp>();
	list.add(new emp());
	Comparable.

元注解
	表示我们的注解可以用在哪些地方
	@target(定义注解的生效范围，让其作用在方法或者类或者变量上)value ElementType.作业域

	@Retention 表示我们的注解在什么地方还有效 value RetentPolicy.三个作用域中的一个

	@Documented 表示是否正常文档

	@Inherited 表示是否被子类继承