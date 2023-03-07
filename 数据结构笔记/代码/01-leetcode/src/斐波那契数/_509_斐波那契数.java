package 쳲�������;

public class _509_쳲������� {
	
	/**
	 * �������Է��̽ⷨ
	 * @param n
	 * @return
	 */
	int fib1(int n) {

        if(n < 2) return n;

        int first = 0;
        int second = 1;

        while(n-- > 1) {
            second += first;
            first = second - first;
        }
        return second;
    }
	
	/**
	 * ���Է��̽ⷨ
	 * @param n
	 * @return
	 */
    public int fib(int n) {
        double c = Math.sqrt(5);
        return (int)((Math.pow((1 + c) / 2, n) - Math.pow((1 - c) / 2, n)) / c);
    }
}
