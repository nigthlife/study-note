public class TestFactorial{
	
	public static void main(String[] args){
		
		//����׳�
		int result = factorial(4);
		
		System.out.println(result);
		
	}
	
	//����n�Ľ׳�
	public static int factorial(int n){
		
		if(n == 1){
			return 1;
		}
		
		return n * factorial( n - 1 );
	}
	
	/*
	//����5�Ľ׳�
	public static int getFive(int n){//n = 5
		//�߼�����
		return n * getFour(n-1);
		//return 5 * 24;
	}
	
	//����4�Ľ׳�
	public static int getFour(int n){//n = 4
		return n * getThree(n-1);
		//return 4 * 6;
	}
	
	public static int getThree(int n){//n = 3
		return n * getTwo(n-1);
		//return 3 * 2;
	}
	
	public static int getTwo(int n){//n = 2
		return n * getOne(n-1);
		//return 2 * 1;
	}
	
	
	public static int getOne(int n){//n = 1
		return 1;
	}
	*/
	
}