/**
	�����������ͣ�С��/��������
*/
public class TestType2{
	public static void main(String[] args){
		
		//float �����ȸ����͡�double ˫���ȸ�����
		
		
		double d = 1.2;
		
		System.out.println(d);
		
		
		 double d2 = 1;
		 
		 System.out.println(d2);
		
		
		float f = 1.5F; //�κΡ�С������ֵ��Ĭ�����Ͷ���double�����Ҫ�洢��float�����У�����ʾ׷�ӡ�F��
		
		System.out.println(f);
		
		//��ѧ������
		double d3 = 2E3; // 2 * 10 ^ 3
		System.out.println(d3);
		
		double d4 = 2E7; // 2 * 10 ^ 7   20000000.0
		System.out.println(d4);
		
		float f2 = 5E4F; // 5 * 10 ^ 4 ׷��F����float
		System.out.println(f2);
		
		
		//ȡֵ��Χ�Ĳ���
		
		//float����ȡֵ��Χ��0.0000000000000000000000000000000000000000000014F ~ 340000000000000000000000000000000000000.0F
		
		float floatMin = 0.0000000000000000000000000000000000000000000014F; //float����С����
		
		float floatMax = 340000000000000000000000000000000000000.0F; //float���������
		
		System.out.println(floatMin);
		
		System.out.println(floatMax);
		
		
		//float����ȡֵ��Χ��-340000000000000000000000000000000000000.0F ~ -0.0000000000000000000000000000000000000000000014F
		
		float floatMin2 = -340000000000000000000000000000000000000.0F;//��ʮ��ǧ�����׾��򡣡�������������
		
		float floatMax2 = -0.0000000000000000000000000000000000000000000014F;
		
		System.out.println(floatMin2);
		
		System.out.println(floatMax2);
		
		
		//double����ȡֵ��Χ��
		double doubleMin = 4.9E-324;//0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000049;
		double doubleMax = 1.7E308;//1700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0;
		
		System.out.println(doubleMin);
		System.out.println(doubleMax);
		
	}
}