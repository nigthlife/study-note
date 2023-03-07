package 栈;

import java.util.Stack;

/**
 * https://leetcode-cn.com/problems/score-of-parentheses/submissions/
 * @author 夜生情
 *
 */
public class _856_括号的分数 {
	
	/**
	 * 使用统计
	 * @param s
	 * @return
	 */
	public int scoreOfParentheses1(String s) {
        
        int ans = 0, bal = 0;

        for (int i = 0; i < s.length(); ++i) {

        
            if (s.charAt(i) == '(') {
                bal++;
            } else {
                bal--;
                if (s.charAt(i-1) == '(')
                    ans += 1 << bal;
            }
        }

        return ans;  
    }

	
	/**
	 * 使用栈
	 * @param s
	 * @return
	 */
	public int scoreOfParentheses(String s) {

        Stack<Integer> stack = new Stack();

        // 记录分数
        stack.push(0);

        // 将字符串转换成字符数组，遍历
        for (char c: s.toCharArray()) {

            // 判断当前字符是否是左括号
            if (c == '(')
                stack.push(0);
            // 如果为右括号
            else {
                // 移除堆栈顶部的对象，并作为此函数的值返回该对象。
                int v = stack.pop();
                int w = stack.pop();

                stack.push(w + Math.max(2 * v, 1));
            }
        }

        return stack.pop();
    }
}
