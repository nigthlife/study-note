class X
{
public static void main(String[] args) {
    float f1 = 9 % 4;// 保存取余后浮点类型的结果
    double da = 9 + 4.5; // 双精度加法
    double db = 9 - 3.0; // 双精度减法
    double dc = 9 * 2.5; // 双精度乘法
    double dd = 9 / 3.0; // 双精度除法
    double de = 9 % 4; // 双精度取余

    System.out.println("整数的算术运算"); // 整数的加、减、乘、除和取余
    System.out.printf("9+4=%d \n", 9 + 4);
    System.out.printf("9-4=%d \n", 9 - 4);
    System.out.printf("9*4=%d \n", 9 * 4);
    System.out.printf("9/4=%d \n", 9 / 4);
    System.out.printf("9%%4=%d \n", 9 % 4);

    System.out.println("\n浮点数的算术运算"); // 浮点数的加、减、乘、除和取余
    System.out.printf("9+4.5f=%f \n", 9 + 4.5f);
    System.out.printf("9-3.0f=%f \n", 9 - 3.0f);
    System.out.printf("9*2.5f=%f \n", 9 * 2.5f);
    System.out.printf("9/3.0f=%f \n", 9 / 3.0f);
    System.out.printf("9%%4=%f \n", f1);

    System.out.println("\n双精度数的算术运算"); // 双精度数的加、减、乘、除和取余
    System.out.printf("9+4.5=%4.16f \n", da);
    System.out.printf("9-3.0=%4.16f \n", db);
    System.out.printf("9*2.5=%4.16f \n", dc);
    System.out.printf("9/3.0=%4.16f \n", dd);
    System.out.printf("9%%4=%4.16f \n", de);

    System.out.println("\n字符的算术运算"); // 对字符的加法和减法
    System.out.printf("'A'+32=%d \n", 'A' + 32);
    System.out.printf("'A'+32=%c \n", 'A' + 32);
    System.out.printf("'a'-'B'=%d \n", 'a' - 'B');
}
}