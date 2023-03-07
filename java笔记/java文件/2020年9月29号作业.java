
class register{
	public static void log(){
		System.out.println("***欢迎来到注册系统***");
		Scanner input = new Scanner(System.in);
		while(true){
			System.out.print("请输入用户名：");
			String userName = input.next();
			System.out.print("请输入密码");
			String password = input.next();
			System.out.print("请在此输入密码：");
			String passwords = input.next();
			if(userName.length() >3 && password.length() > 6){
				System.out.println("用户名长度不能小于3，密码长度不能小于6");
			}else if(password != passwords){
				System.out.println("两次输入的密码不相同！");
			}else{
				System.out.println("注册成功！请牢记用户名和密码");
			}
		}
	}
}

class Demo{
    public static void main(String[] args){
        Scanner input = new Scanner(System.in);
        System.out.print("请输入Java文件名：");
        String name = input.next();
        System.out.print("请输入你的邮箱：");
        String email = input.next();
        if(!name.endsWith(".java")){
            System.out.println("文件格式错误！");
        }
        //如果文件中点不在@字符后面就判断邮箱错误
        if(email.contains("@")){
            int str = email.indexOf("@");
            int strs = email.indexOf(".");
            if(strs < str){
                System.out.println("E-mail无效" );
                System.out.println("作业提交失败！");
            }else{
                System.out.println("作业提交成功！");
            }
        }
    }
}

class Test{
    public static void main(String[] args){
        Scanner input = new Scanner(System.in);
        System.out.print("请输入一个字符串：");
        String string = input.nextLine();
        System.out.print("请输入需要查找的字符：");
        char seek = input.next().charAt(0);
        int count = 0;
        for(int i = 0;i < string.length();i++){
            if(string.charAt(i) == seek){
                count++;
            }
        }
        System.out.println(string+"中包含"+count+"个"+seek);
    }
}