import java.util.Scanner;

public class TestSearch{
	
	public static void main(String[] args){
		
		Scanner input = new Scanner(System.in);
		
		
		System.out.println("������һ��������");
		
		int n = input.nextInt();
		
		
		int[] numbers = new int[]{1,2,3,4,5,6,7};
		
		int index = -1;//����n��δ������������
		
		//ѭ�����ҵĹ���
		for(int i = 0 ; i < numbers.length ; i++){
			if(numbers[i] == n){
				//����
				index = i;//�ı�index������n�����ֵ��±�
				break;
			}
		}
		
		System.out.println(index);
		
	}
}