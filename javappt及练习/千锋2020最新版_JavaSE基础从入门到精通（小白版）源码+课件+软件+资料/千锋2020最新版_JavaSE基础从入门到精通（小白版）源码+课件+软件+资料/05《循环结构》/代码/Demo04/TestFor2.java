import java.util.Scanner;

public class TestFor2{
	
	public static void main(String[] args){
		
		Scanner input = new Scanner(System.in);
		
		//����5λͬѧ��ƽ����

		
		double sum = 0.0;//�ܺ�
		
		for(int i = 1; i <= 5; i++){
			
			//1.ѭ������̨¼�����
			System.out.println("�������" + i + "λͬѧ�ĳɼ���");
			
			double score = input.nextDouble();
			
			//2.�ۼ��ܺ�
			sum = sum + score;
			
		}
		
		double avg = sum / 5;
		
		System.out.println("ƽ���֣�" + avg);
		
	}
}