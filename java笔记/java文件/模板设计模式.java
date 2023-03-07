public class template{
	public static void main(String[] args){
		BaseMananger am = new UserMananger();
		am.action("admin","add");
	}
}

abstract class BaseMananger{
	public void action(String name,String method){
		if("admin".equals(name)){

		}else{
			System.out.println("您没有操作权限，请联系管理员");
		}
	}
	public abstract void execute(String method);
}

class UserMananget extends BaseMananger{
	public void execute(String method){
		if("add".equals(method)){
			System.out.println("执行了添加操作");
		}else if("del".equals(method)){
			System.out.println("执行了删除操作");
		}

	}
}