public class TestMultipleIf{
	
	public static void main(String[] args){
		
		/*
			����Ԥ����ѡ������
			
			Ԥ�� > 100��   ����S��
			Ԥ�� > 50��     ����5ϵ
			Ԥ�� > 10��     �µ�A4L
			Ԥ�� < 10��	  �ݰ������г�
		*/
		
		int money = 110; //��λ����
		
		if(money > 100){
			System.out.println("����S��");
		}else if(money > 50){
			System.out.println("����5ϵ");
		}else if(money > 10){
			System.out.println("�µ�A4L");
		}else{
			System.out.println("�ݰ������г�");
		}

		System.out.println("�������...");
		
	}
}