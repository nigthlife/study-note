public class TestOperation1{
	
	public static void main(String[] args){
		
		int a = 10;
		
		int b = 3;
		
		System.out.println( a / b );//���� = 3
		
		System.out.println( a % b );//���� = 1
		
		
		
		double d = 10.0;
		
		int c = 3;
		
		System.out.println(d / c);//���� 3.33.......
		
		
		
		
		int num1 = 10;
		
		num1++;//����1
		
		System.out.println(num1);
		
		
		
		int num2 = 10;
		
		num2--;//�Լ�1
		
		System.out.println(num2);
		
		
		
		int num3 = 5;
		
		//ǰ++ ����++���ٴ�ӡ�������ֵ
		
		//��++ �� �ȴ�ӡ��ǰֵ����++
		
		System.out.println( ++num3 );
		
		System.out.println( num3 );
		
		
		int num4 = 100;
		
		//ǰ++ ����++���ٸ�ֵ
		
		//��++ �� �ȸ�ֵ����++
		
		int num5 = num4++;
		
		System.out.println(num5);
		
		System.out.println(num4);
		
		
	}
}