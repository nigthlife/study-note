public class TestReturn{
	
	public static void main(String[] args){
		
		int result = add(5,10);// int result = 15;
		
		System.out.println(result);
		
		//�ڼ�����5+10���ܺ�֮�󣬼�����20����������
		
		
		int result2 = add( result , 20);
		
		System.out.println(result2);
		
	}
	
	public static int add(int num1 , int num2){
		int sum = num1 + num2;
		return sum;
	}
	
	
}