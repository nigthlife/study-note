//测试类
public class agency{
	public static void main(String[] args){
		UserAction user = new UserAction();
		ActionProxy proxy = new ActionProxy(user);
		proxy.doAction();
	}
}

//静态代理类
class ActionProxy implements Action{
	private Action target;
	//创建业务类实现对象
	public ActionProxy(Action target){
		this.target = target;
	}
	public void doAction(){
		long startTime = System.curremtTimeMillis();
		target.doAction();
		long endTime = System.currentTimeMillis();
		System.out.println("共耗时"+(endTime - startTime));
	}
}

//
interfacee Action{
	public void doAction();
}

//业务实现类
class UserAction implements Action{
	public void doAction(){
		for(int i = 0; i < 10; i++){
			System.out.println("用户开始工作"+i)
		}
	}
}