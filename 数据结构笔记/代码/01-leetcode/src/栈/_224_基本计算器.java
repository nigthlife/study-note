package ջ;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedList;

/**
 * https://leetcode-cn.com/problems/basic-calculator/
 * @author ҹ����
 *
 */
public class _224_���������� {

	/**
	 * �ٷ��ⷨ
	 * @param s
	 * @return
	 */
	public int calculate(String s) {
		
		// ����ջ��Ԫ�ؼ�¼�˵�ǰλ��������ÿ������������ͬ�γɡ��ķ��š����磬�����ַ��� 1+2+(3-(4+5))
        Deque<Integer> ops = new LinkedList<Integer>();
        
        ops.push(1);
        
        // ������ǰ���ķ���
        int sign = 1;

        int ret = 0;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (s.charAt(i) == ' ') {
                i++;
            } else if (s.charAt(i) == '+') {
                sign = ops.peek();
                i++;
            } else if (s.charAt(i) == '-') {
                sign = -ops.peek();
                i++;
            } else if (s.charAt(i) == '(') {
                ops.push(sign);
                i++;
            } else if (s.charAt(i) == ')') {
                ops.pop();
                i++;
            } else {
                long num = 0;
                while (i < n && Character.isDigit(s.charAt(i))) {
                    num = num * 10 + s.charAt(i) - '0';
                    i++;
                }
                ret += sign * num;
            }
        }
        return ret;
    }

	/**
	 * ˫ջ�ⷨ
	 * @param s
	 * @return
	 */
	 public int calculate1(String s) {
		 
	        // ������е�����
	        Deque<Integer> nums = new ArrayDeque<>();
	        
	        // Ϊ�˷�ֹ��һ����Ϊ���������� nums �Ӹ� 0
	        nums.addLast(0);
	        
	        // �����еĿո�ȥ��
	        s = s.replaceAll(" ", "");
	        
	        // ������еĲ��������� +/-
	        Deque<Character> ops = new ArrayDeque<>();
	        
	        // ��ȡ�ַ�������
	        int n = s.length();
	        
	        // ����ַ���
	        char[] cs = s.toCharArray();
	        
	        
	        for (int i = 0; i < n; i++) {
	        	
	        	// ȡ���ַ�
	            char c = cs[i];
	            if (c == '(') {
	            	
	            	// ��Ų�����
	                ops.addLast(c);
	            } else if (c == ')') {
	            	
	                // ���㵽���һ��������Ϊֹ
	                while (!ops.isEmpty()) {
	                	
	                	// ȡ�����һ��Ԫ��
	                    char op = ops.peekLast();
	                    if (op != '(') {
	                        calc(nums, ops);
	                    } else {
	                        ops.pollLast();
	                        break;
	                    }
	                }
	            } else {
	                if (isNum(c)) {
	                    int u = 0;
	                    int j = i;
	                    // ���� i λ�ÿ�ʼ�����������������ȡ�������� nums
	                    while (j < n && isNum(cs[j])) u = u * 10 + (int)(cs[j++] - '0');
	                    nums.addLast(u);
	                    i = j - 1;
	                } else {
	                    if (i > 0 && (cs[i - 1] == '(' || cs[i - 1] == '+' || cs[i - 1] == '-')) {
	                        nums.addLast(0);
	                    }
	                    // ��һ���²���Ҫ��ջʱ���Ȱ�ջ�ڿ�����Ķ�����
	                    while (!ops.isEmpty() && ops.peekLast() != '(') calc(nums, ops);
	                    ops.addLast(c);
	                }
	            }
	        }
	        while (!ops.isEmpty()) calc(nums, ops);
	        return nums.peekLast();
	    }
	    void calc(Deque<Integer> nums, Deque<Character> ops) {
	        if (nums.isEmpty() || nums.size() < 2) return;
	        if (ops.isEmpty()) return;
	        int b = nums.pollLast(), a = nums.pollLast();
	        char op = ops.pollLast();
	        nums.addLast(op == '+' ? a + b : a - b);
	    }
	    boolean isNum(char c) {
	        return Character.isDigit(c);
	    }

}
