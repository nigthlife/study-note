public class TestNestedFor3{
	
	public static void main(String[] args){
		
		//��ӡֱ��������
		
		/*
		
		*			j <= 1
		**			j <= 2
		***		j <= 3
		****		j <= 4
		*****		j <= 5
		
		-----------------------
		
		*
		**
		***
		****
		*****
		
		*/
		
		//����������
		for(int i = 1 ; i <= 5 ; i++){ // i = 6
			
			//�ڲ��������
			for(int j = 1 ; j <= i ; j++){ //
				System.out.print("*");
			}
			System.out.println();
			
		}
		
		System.out.println("�������");
		
	}
}