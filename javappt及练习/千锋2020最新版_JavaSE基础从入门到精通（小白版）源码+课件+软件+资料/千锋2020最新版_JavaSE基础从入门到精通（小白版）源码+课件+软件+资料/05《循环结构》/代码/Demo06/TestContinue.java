import java.util.Scanner;

public class TestContinue{
	
	public static void main(String[] args){
		
		Scanner input = new Scanner(System.in);
		
		//����̨¼��5λͬѧ�ɼ���������κ�һλͬѧ�ĳɼ������Ƿ����ݣ�������0~100֮������֣�ʱ���������ε�ͳ�ƣ�������һ��ѭ������

		double sum = 0.0;
		
		for(int i = 1; i <= 5; ){
			System.out.println("�������" + i + "λͬѧ�ĳɼ���");
			
			double score = input.nextDouble();
			
			if(score < 0 || score >100.0){
				//�Ƿ�����
				continue;
			}
			
			sum = sum + score;
			
			i++;
		}
		
		double avg = sum / 5;
		
		System.out.println("ƽ���֣�" + avg);
	}
}