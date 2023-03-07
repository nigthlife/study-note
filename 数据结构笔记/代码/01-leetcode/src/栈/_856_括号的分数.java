package ջ;

import java.util.Stack;

/**
 * https://leetcode-cn.com/problems/score-of-parentheses/submissions/
 * @author ҹ����
 *
 */
public class _856_���ŵķ��� {
	
	/**
	 * ʹ��ͳ��
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
	 * ʹ��ջ
	 * @param s
	 * @return
	 */
	public int scoreOfParentheses(String s) {

        Stack<Integer> stack = new Stack();

        // ��¼����
        stack.push(0);

        // ���ַ���ת�����ַ����飬����
        for (char c: s.toCharArray()) {

            // �жϵ�ǰ�ַ��Ƿ���������
            if (c == '(')
                stack.push(0);
            // ���Ϊ������
            else {
                // �Ƴ���ջ�����Ķ��󣬲���Ϊ�˺�����ֵ���ظö���
                int v = stack.pop();
                int w = stack.pop();

                stack.push(w + Math.max(2 * v, 1));
            }
        }

        return stack.pop();
    }
}
