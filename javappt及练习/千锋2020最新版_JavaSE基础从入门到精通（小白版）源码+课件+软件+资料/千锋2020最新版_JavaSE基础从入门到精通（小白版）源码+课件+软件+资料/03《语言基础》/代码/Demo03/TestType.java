/** 
	�����������ͣ�������
*/
public class TestType{
	public static void main(String[] args){
		
		//�������� ������ = ֵ;
		
		byte b = 127;// -128 ~ 127 ������256��������
		
		System.out.println(b);
		
		
		short s = 32767;//-32768 ~ 32767 ������65536��������
		
		System.out.println(s);
		
		
		int i = 2147483647;//-2147483648 ~ 2147483647 ������42�ڶ��������
		
		System.out.println(i);
		
		
		
		//Java�����еġ���������ֵ����Ĭ��������int������������ֵ����int��ȡֵ��Χʱ�������ѡ������������
		
		long l1 = 2147483648L;//��ʾ��֪JVM����ֵΪlong����
		long l2 = 9223372036854775807L;//-9223372036854775808L ~ 9223372036854775807L
		
		System.out.println(l1);
		System.out.println(l2);
	}
}