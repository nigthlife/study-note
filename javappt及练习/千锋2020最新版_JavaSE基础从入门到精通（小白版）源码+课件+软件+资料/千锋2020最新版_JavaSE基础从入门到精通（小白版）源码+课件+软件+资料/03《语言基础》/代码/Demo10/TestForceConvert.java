public class TestForceConvert{
	
	public static void main(String[] args){
		
		//�����㹻����������
		short s = 123;
		
		byte b = (byte)s;//ǿ������ת��������������
		
		System.out.println(b);

		//���Ȳ��������ݽض�
		
		short s2 = 257;
		
		byte b2 = (byte)s2;//ǿ������ת�������ݽضϣ�
		
		System.out.println(b2);

		
		short s3 = 130;
		
		byte b3 = (byte)s3;
		
		System.out.println(b3);
		
		
		//С�� ǿת ����
		
		double d = 2.999;
		
		int i = (int)d;
		
		System.out.println(i);
		
		
		//�ַ� ǿת ����
		
		char c = 'A';
		
		int i2 = c;//�Զ�����ת��
		
		System.out.println(i2);
		
		
		char c2 = (char)i2;//ǿ������ת��
		
		System.out.println(c2);
		
		
		//�ַ�������ת����ע������
		
		short s4 = -1;// -32768 ~ 32767
		
		char c3 = (char)s4;//ǿ������ת��
		
		System.out.println(c3);
	}
}