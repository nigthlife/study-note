import java.util.Scanner;

public class TestBreak{
	
	public static void main(String[] args){

		Scanner input = new Scanner(System.in);
		
		//����̨¼��5λͬѧ�ɼ���������κ�һλͬѧ�ĳɼ������Ƿ����ݣ�������0~100֮������֣�ʱ����ֱ���˳�����ѭ������

		double sum = 0.0;
		
		boolean flag = true;//�Ϸ�
		
		for(int i = 1; i <= 5; i++){

			System.out.println("�������" + i + "λͬѧ�ĳɼ���");
			
			double score = input.nextDouble();

			if(score < 0 || score > 100.0){
				flag = false;//�Ƿ�����
				break;
			}
			
			sum = sum + score;
			
		}
		
		if( flag == true ){ //����flag��Ǿ����Ƿ���Ҫ��������ƽ����
			double avg = sum / 5;
		
			System.out.println("ƽ���֣�" + avg);
		}else{
			System.out.println("�Ƿ����ݣ����������г������ƽ����");
		}
		
		
		
	}
}