package 栈;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedList;

/**
 * https://leetcode-cn.com/problems/basic-calculator/
 * @author 夜生情
 *
 */
public class _224_基本计算器 {

	/**
	 * 官方解法
	 * @param s
	 * @return
	 */
	public int calculate(String s) {
		
		// 其中栈顶元素记录了当前位置所处的每个括号所「共同形成」的符号。例如，对于字符串 1+2+(3-(4+5))
        Deque<Integer> ops = new LinkedList<Integer>();
        
        ops.push(1);
        
        // 代表「当前」的符号
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
	 * 双栈解法
	 * @param s
	 * @return
	 */
	 public int calculate1(String s) {
		 
	        // 存放所有的数字
	        Deque<Integer> nums = new ArrayDeque<>();
	        
	        // 为了防止第一个数为负数，先往 nums 加个 0
	        nums.addLast(0);
	        
	        // 将所有的空格去掉
	        s = s.replaceAll(" ", "");
	        
	        // 存放所有的操作，包括 +/-
	        Deque<Character> ops = new ArrayDeque<>();
	        
	        // 获取字符串长度
	        int n = s.length();
	        
	        // 拆分字符串
	        char[] cs = s.toCharArray();
	        
	        
	        for (int i = 0; i < n; i++) {
	        	
	        	// 取出字符
	            char c = cs[i];
	            if (c == '(') {
	            	
	            	// 存放操作符
	                ops.addLast(c);
	            } else if (c == ')') {
	            	
	                // 计算到最近一个左括号为止
	                while (!ops.isEmpty()) {
	                	
	                	// 取出最后一个元素
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
	                    // 将从 i 位置开始后面的连续数字整体取出，加入 nums
	                    while (j < n && isNum(cs[j])) u = u * 10 + (int)(cs[j++] - '0');
	                    nums.addLast(u);
	                    i = j - 1;
	                } else {
	                    if (i > 0 && (cs[i - 1] == '(' || cs[i - 1] == '+' || cs[i - 1] == '-')) {
	                        nums.addLast(0);
	                    }
	                    // 有一个新操作要入栈时，先把栈内可以算的都算了
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
