class Deng
{
	public static void main(String args[])
	{
	    ‌int munber1,number2;	//定义变量，保存输入的俩个数
	    System.out.print("请输入第一个整数(number1)：");
	    Scanner input = new Scanner(System.in);
	    number1 = input.nextInt();	//输入第一个数
	    System.out.print("请输入第二个整数(number2)：");
	    input = new Scanner(System.in);
	    number2 = input.extInt();	//输入第二个数
	    System.out.printf("number1=%d,number2=%\n",number1,number2);
		//输出这俩个数
		//判断用户输入的俩个数据是否相等
	    if(number1 == number2)
		{
		     System.out.println("number1 和 number2 相等。");
		}
		//判断用户输入的俩个数字是否相等
	    if(number1 != number2)
		{
		    System.out.println("number1 和 number2 不相等。");
		    //判断用户输入的数字是否大于2
		    if(number1 > number2)
			{
			    Ststem.out.println("number1 大于 number2.");
			}
		    //判断用户输入的数字是否小于2
		    if(number1 < number2)
			{
			    System.out.println("number1 小于 number2。");
			}
		}
	
	}

}