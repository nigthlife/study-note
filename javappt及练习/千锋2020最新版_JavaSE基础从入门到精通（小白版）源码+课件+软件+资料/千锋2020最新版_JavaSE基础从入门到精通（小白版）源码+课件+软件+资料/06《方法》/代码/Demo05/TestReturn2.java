public class TestReturn2{
	
	public static void main(String[] args){
		
		//double result = calc(1.5 , 10.2);
		
		//System.out.println("��������" + result);
		
		//-------------------------------------------
		
		//String str = isEven(10);
		
		//System.out.println(str);
		
		//-------------------------------------------
		
		show();
		
		
	}
	
	
	public static double calc(double a , double b){
		double sum = a + b;
		System.out.println("�������");
		return sum;//������ǰ�����������з���ֵ�����ص��������ô�
	}
	
	public static String isEven(int num){
		if(num % 2 == 0){
			return "ż��";
		}else{
			return "����";
		}
	}
	
	public static void show(){
		for(int i = 1 ; i <= 10 ; i++){
			System.out.println("��ǰֵ" + i);
			if(i == 5){
				return;//������ǰ���������ص��������ó�
			}
		}
		System.out.println("show() .............");
	}
}