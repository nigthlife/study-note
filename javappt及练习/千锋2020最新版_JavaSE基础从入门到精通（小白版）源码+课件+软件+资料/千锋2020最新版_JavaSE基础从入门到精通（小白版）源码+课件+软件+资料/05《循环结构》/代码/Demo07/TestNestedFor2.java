import java.util.Scanner;

public class TestNestedFor2{
	
	public static void main(String[] args){
		
		Scanner input = new Scanner(System.in);
	
		for(int k = 1 ; k <= 3 ; k++){
			
			System.out.println("---��"+k+"����---");
			
			//��һ���࣬5λͬѧ��ƽ���ɼ�
			double sum = 0.0;
			
			for(int i = 1 ; i <= 5 ; i++){
				
				System.out.println("�������" + i +"λͬѧ�ĳɼ���");
				
				double score = input.nextDouble();
				
				sum += score;
				
			}
			
			double avg = sum / 5;
			
			System.out.println("��" + k + "��5λͬѧ��ƽ���֣�" + avg);
			
		}
		
	}
}