//package ������Դ�ļ�������

import java.util.Scanner;//1.�����ⲿ�ļ�

public class TestScanner{
	
	public static void main(String[] args){
		
		//2.����Scanner���͵ı���
		Scanner input = new Scanner(System.in);
		
		System.out.println("������һ��������");
		
		//3.ʹ��
		int i = input.nextInt(); //����̨��ȡһ������

		System.out.println("�������ֵΪ��" + i);
	}
}