


import java.util.Random;
import java.util.Scanner;
public class pass{
	public static void main(String ages[]){
		//通过Random类中的nextInt(int n) 方法，生成一个0-9的随机数
		int num = new Random().nextInt(10);
		System.out.println("随机数已生成！");
		//输入猜的数字
		System.out.println("----请输入你猜的数字----");

		Scanner sc= new Scanner(System.in);
		int cnum = sc.nextInt();
		//对猜的数字进行判断
		//猜对了就退出
		while(cnum != num){
	
		
			if(cnum > num){
				System.out.println("您猜大了！");
			}else{
				System.out.println("您猜小了！");
			}
			cnum = sc.nextInt();
		}
		System.out.println("恭喜您，答对了！");
	}
}
