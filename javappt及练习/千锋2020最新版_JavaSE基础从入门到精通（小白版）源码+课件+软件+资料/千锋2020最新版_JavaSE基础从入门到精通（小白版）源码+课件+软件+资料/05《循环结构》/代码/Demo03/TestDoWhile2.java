import java.util.Scanner;

public class TestDoWhile2{
	
	public static void main(String[] args){
		
		Scanner input = new Scanner(System.in);
		
		//ѭ��������ѧ����д���롢��ʦ��������
		
		char answer = 'y';//�����ʼֵ
		
		do{
			System.out.println("��дһ��...");
			
			System.out.println("���ʦ�������");
			
			answer = input.next().charAt(0);//����̨��ȡ'y'����'n'
		}while( answer != 'y' );
		
		System.out.println("�������...");
		
	}
}