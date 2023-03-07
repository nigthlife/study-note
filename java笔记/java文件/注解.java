class peakedness{
	private String name;
	private int id;
	private String sex;
	public peakedness(){}
	public peakedness(String name){
		this.name = name;
	}
	public peakedness(Stirng name,int id){
		this.name = name;
		this.id = id;
	}
	public peakedness(String name,int id,String sex){
		this.name = name;
		this.id = id;
		this.sex = sex;
	}
	public String getName(){
		return name;
	}
	public void setName(String name){
		this.name = name;
	}
	public void setId(int id){
		this.id = id;
	}
	public int getId(){
		return id;
	}
	public void setSex(String sex){
		this.sex = sex;
	}
	public String getSex(){
		return sex;
	}
	public void printName(){
		System.out.println("我的名字是：");
	}
	public void printId(){
		System.out.println("我的id但是：");
	}
	public void printSex(){
		System.out.println("我的性别是：");
	}

}


@target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIEM)
public @interface Mypeakedness{
	String className();
	String methodName();
	Stirng fieldName();
}

@Mypeakedness(className = "peakedness",methodName = "printName",fieldName = "")
public calss peskednessTest{
	public static void main(String[] args){
		Class clazz = peskednessTest.class;

		//通过文件字节码文件获取注释对象
		Mypeakedness myp = clazz.getAnnotation(Mypeakedness.class);
		
		//获取注解对象中定义的抽象方法，获取返回值
		String ClassName = myp.getclassName();
		String MedthodName = myp.getmethodName();

		//把获取的类加载进内存
		Class clazz1 = Class.forName(ClassName);
		//创建ClassName对象
		Object obj = clazz1.newInstance();

		//通过注解指定的方法名获取该方法
		Medthod method = clazz1.getMethod(MedthodName);

		//通过获取的方法执行方法
		method.invole(obj);

	}
}
	
