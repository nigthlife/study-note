public class ConstructorTest{
	public static void main(Stirng[] args){

		//方法一，调用Class的newInstance方法，仅适用于无参构造方法
		Class clazz = Class.forName("Studetn");
		Object obj = clazz.newInstance();

		//方法二，通过Constructor的newInstance()方法
		//先使用Class对象获取指定的Constructor对象
		//再调用Constructor对象的newInstance()方法来创建该Class对象对应类的对象
		//通过该方法可选择使用指定构造方法来创建对象
		Class clazz = Class.forName("Studetn");
		Constructor cons = clazz.getConstructor(new Class[]
			{String.class,int.class,float.class});
		Object obj = cons.newInstance(new Object[] {"II",12,"56.5f"});
		System.out.println(obj);

		//也可以调用无参构造方法，只是比方法1复杂
		obj = clazz.getConstructor(new Class[]{}).
			newInstance(new Object[]{});
		obj = clazz.getConstructor().newInstance();//相当于执行Student stu = new Studnet();
		System.out.println(obj);
	}
}