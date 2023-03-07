
//测试类
public class plant{
	public static void main(String[] args){
		Product phone = ProductFactory.getProduct(phone);//创建phone对象
		if(null != phone){
			phone.work();
		}
	}
}


//创建工厂类
class ProductFactory{
	public static Product getProduct(String name){
		if("phone".equals(name)){
			return new Phone();
		}else if("computer".equals(name)){
			return new Computer();
		}else{
			return null;
		}
	}
}


interfect Product{
	public void work();	
}

class Phone implements Product{
	public void work(){
		System.out.println("手机开始工作...");
	}
}

class Computer implements Product{
	public void work(){
		System.out.println("电脑开始工作...");
	}
}