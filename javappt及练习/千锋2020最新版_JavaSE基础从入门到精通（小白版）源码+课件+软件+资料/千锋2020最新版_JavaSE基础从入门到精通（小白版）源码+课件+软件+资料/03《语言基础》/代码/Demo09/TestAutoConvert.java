public class TestAutoConvert{
	
	public static void main(String[] args){
		
		//���� - ����
		
		short s = 123;
		
		int i = s;//��Դ����ֵ���뵽Ŀ�����ͱ����У��Զ�����ת����
		
		System.out.println(i);
		
		
		byte b = 100;
		
		short s2 = b;//�Զ�����ת��
		
		System.out.println(s2);
		
		
		//С�� - С��
		
		float f = 100.0F;
		
		double d = f;//�Զ�����ת��
		
		System.out.println(d);
		
		
		//С�� - ����
		
		int i2 = 100;
		
		double d2 = i2;//�Զ�����ת��
		
		System.out.println(d2);
		
		
		//�ַ� - ����
		
		char c = 'A';
		
		int i3 = c;//�Զ�����ת��
		
		System.out.println(i3);
		
		
		//�ַ� - С��
		
		char c2 = 'a';
		
		double d3 = c2;
		
		System.out.println(d3);
		
	
		//boolean�޷����������ͽ���ת��
		
		boolean bool = true;//true | flase
		
		int i4 = bool;//�����ݵ�����
	
	}
}







