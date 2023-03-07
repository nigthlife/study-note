package cn.mldn;

import java.util.Scanner;

/**
 * 
 * @author 黄强
 *Pet：定义一个宠物抽象类，类中有属性：name：宠物名称，healthIndex：宠物健康值，默认值为60，
 *intimacy：宠物与主人的亲密度，默认值为20。这宠物类中有一个eat()抽象方法，实现根据不同的宠物来实现不同的喂食功能。
 *有一个play抽象方法，实现根据不同的宠物来实现不同的玩耍功能。
 */
abstract class Pet{
	
	private String name;//宠物名称
	private int healthIndex = 60;//宠物健康值
	private int intimacy = 20;//亲密度
	
	public Pet(){};
	
	public Pet(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public int getHealthIndex() {
		return healthIndex;
	}
	
	public void setHealthIndex(int healthIndex) {
		this.healthIndex = healthIndex;
	}
	
	public int getIntimacy() {
		return intimacy;
	}
	
	public void setIntimacy(int intimacy){
		
		this.intimacy = intimacy;
	}
	
	/**
	 * 方法功能：实现根据不同的宠物来实现不同的喂食功能。
	 */
	public abstract void eat();
	
	/**
	 * 方法功能：实现根据不同的宠物来实现不同的玩耍功能。
	 */
	public abstract void play();
	
	@Override
	public String toString() {
		
		return "宠物名称：" + this.name + 
				"，宠物健康值：" + this.healthIndex + 
				"，宠物与主人的亲密度:" + this.intimacy;
	}
}
/**
 * 
 * @author 黄强
 *Dog：宠物狗类，此类继承Pet类，并实现eat()抽象方法，调用eat()方法完成宠物狗的喂食。
 */
class Dog extends Pet{
	
	@Override
	public void eat() {
		
		this.setHealthIndex(this.getHealthIndex() + 3);
		System.out.println("宠物狗喂食成功，健康值为：" + this.getHealthIndex());
	}

	@Override
	public void play() {
		
		this.setHealthIndex(this.getHealthIndex() - 10);
		this.setIntimacy(this.getIntimacy() + 5);
		System.out.println("主人和狗狗玩接飞盘游戏，狗狗的健康值为：" + this.getHealthIndex() + 
				"，狗狗与主人的亲密度为：" + this.getIntimacy());
	}
}

/**
 * 
 * @author 黄强
 *Cat：宠物猫类，此类继承Pet类，并实现eat()抽象方法，调用eat()方法完成宠物猫的喂食。
 */
class Cat extends Pet{

	@Override
	public void eat() {
		
		this.setHealthIndex(this.getHealthIndex() + 4);
		System.out.println("宠物猫喂食成功，健康值为：" + this.getHealthIndex());
	}
	
	@Override
	public void play() {
		
		this.setHealthIndex(this.getHealthIndex() - 10);
		this.setIntimacy(this.getIntimacy() + 5);
		System.out.println("主人和猫猫玩接毛球游戏，猫猫的健康值为：" + this.getHealthIndex() + 
				"，猫猫与主人的亲密度为：" + this.getIntimacy());
	}
}

/**
 * 
 * @author 黄强
 *Dog：宠物企鹅类，此类继承Pet类，并实现eat()抽象方法，调用eat()方法完成宠物企鹅的喂食。
 */
class Penguin extends Pet{

	@Override
	public void eat() {
		
		this.setHealthIndex(this.getHealthIndex() + 5);
		System.out.println("宠物企鹅喂食成功，健康值为：" + this.getHealthIndex());
	}
	
	@Override
	public void play() {
		
		this.setHealthIndex(this.getHealthIndex() - 10);
		this.setIntimacy(this.getIntimacy() + 5);
		System.out.println("主人和企鹅玩接游泳游戏，企鹅的健康值为：" + this.getHealthIndex() + 
				"，企鹅与主人的亲密度为：" + this.getIntimacy());
	}
}

/**
 * 
 * @author 黄强
 *Factory：工厂类，里面有一个静态的getInstance()方法，此方法的功能：实现根据传入的宠物类名来实例化对应的宠物类对象，
 *并将实例化的宠物类对象向上转型，返回一个Pet类对象。
 */
class Factory{
	
	public static Pet getInstance(String key) throws Exception{
		
		Object obj = null;
		try{
			//根据传入的宠物类型来找到对应的宠物类，注意：宠物的子类必须定义在同一个包中，否则会进入死循环
			Class<?> cla = Class.forName("cn.mldn." + key);
			obj = cla.newInstance();//生成对应的宠物类实例，返回类型为Object类对象
		}catch(Exception e){
			throw new PetException("宠物类型输入错误，请重新输入！");
		}
		
		return (Pet) obj;//向下转型为Pet类对象并返回
	}
}

/**
 * 自定义一个异常类，若Pet类实例化报错时，会实例化此类对象，进行异常信息的描述
 * @author 黄强
 *
 */
class PetException extends Exception{
	
	/**
	 * PetException类的构造方法，根据传递的字符串来调用Exception类的构造方法，实例化一个自定义的异常类对象
	 * @param str：需要输出的异常信息
	 */
	public PetException(String str){
		
		super(str);
	}
}

public class PetTest {

	public static void main(String[] args){
		
		System.out.println("进行宠物喂食功能：");
		isGetPet().eat();
		System.out.println();//换行
		System.out.println("进行宠物玩耍功能：");
		isGetPet().play();
	}
	
	/**
	 * 方法名称：getType
	 * 参数列表：null
	 * 方法功能：实现用户输入一个宠物的类型名称并返回。
	 * @return 返回一个宠物的类型名称
	 */
	public static String getType(){
		
		Scanner sc = new Scanner(System.in);
		System.out.println("请正确输入宠物类型：");
		String type = sc.nextLine();//type用来保存用户输入的宠物类型
		return type;//返回用户输入的宠物类型
	}
	
	/**
	 * 方法名称：getName
	 * 参数列表：null
	 * 方法功能：实现用户输入一个宠物名称并返回。
	 * @return 返回一个宠物名称
	 */
	public static String getName(){
		
		Scanner sc= new Scanner(System.in);
		System.out.println("请输入宠物名称：");
		String name = sc.nextLine();
		return name;
	}
	
	/**
	 * 方法名称：getPet
	 * 参数列表：null
	 * 方法功能：实现用户输入一个宠物的类型名称和宠物名称来实例化一个Pet类对象并返回。
	 * @return 返回一个Pet类对象
	 */
	public static Pet getPet(){
		
		String type = getType();
		Pet pet =null; //保存实例化后的宠物对象
			try {
				//根据输入的宠物类型调用Factory类中的getInstance()方法，此方法会根据传递的类型实例化一个对应的宠物对象并返回
				//但是如果输入的类型与所有宠物的类型都不匹配，则无法实例化一个宠物对象，并且会抛出一个异常，这里使用了try语句处理了异常
				pet = Factory.getInstance(type);
				String name = getName();//让用户输入宠物名称
				pet.setName(name);//调用setter方法进行宠物名称的赋值
			} catch (Exception e) {
				
				e.getMessage();//输出报错信息
			}
		return pet;//如果用户输入的宠物类型错误返回null，否则返回实例化的Pet类对象
	}
	
	/**
	 * 方法名称：isGetPet
	 * 参数列表：null
	 * 方法功能：实现循环调用getPet()方法，如果getPet()方法返回的内容为null，则继续调用此方法，否则返回实例化的Pet类对象
	 * 
	 * @return
	 */
	public static Pet isGetPet(){
		
		Pet pet = null;//保存getPet()方法的返回值
		while(true){
			//调用getPet()方法，并将返回值赋值给pet对象，判断pet对象的内容是否为空，如果不为空，则结束循环
			if((pet = getPet()) != null){
				break;
			}
		}
		return pet;//返回实例化的Pet类对象
	}
}
