import java.util.Scanner;

public class TestScanner2{
	
	public static void main(String[] args){
		
		Scanner input = new Scanner(System.in);
		
		System.out.println("������ֵ��");
		
		int i = input.nextInt();//��������
		
		double d = input.nextDouble();//����С��
		
		String s = input.next();//�����ַ���
		
		char c = input.next().charAt(0);//�����ַ�������һ���������ַ�������ȡ���еĵ�һ���ַ���
		
		
		System.out.println("������" + i);
		System.out.println("С����" + d);
		System.out.println("�ַ�����" + s);
		System.out.println("�ַ���" + c);
		
		
	}
}