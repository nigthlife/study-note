package ջ;

import java.util.HashMap;
import java.util.Stack;

/**
 * https://leetcode-cn.com/problems/valid-parentheses/
 * @author ҹ����
 *
 */
public class _20_��Ч������ {
	
	private static HashMap<Character, Character> map = new HashMap<>();
	
	static {
		map.put('(',')');
		map.put('[',']');
		map.put('{','}');
	}
	
	/**
	 * ������
	 * @param s
	 * @return
	 */
	public boolean isValid3(String s) {
		
		Stack<Character> stack = new Stack<>();
		
		int len = s.length();
		
		for(int i = 0; i < len; i++) {
			char c = s.charAt(i);
			
			if(map.containsKey(c)) {
				stack.push(c);
			}else {
				if(stack.isEmpty()) return false;
				
				if(c != map.get(stack.pop())) return false;

			}
		}
		
		return stack.isEmpty();
	
	}

	/**
	 * ������
	 * @param s
	 * @return
	 */
	public boolean isValid2(String s) {
		 
		Stack<Character> stack = new Stack<>();
		
		int len = s.length();
		
		for(int i = 0; i < len; i++) {
			char c = s.charAt(i);
			
			if(c == '(' || c == '[' || c == '{') {
				stack.push(c);
			}else {
				if(stack.isEmpty()) return false;
				
				char left = stack.pop();
				
				if(left == '(' && c != ')') return false;
				if(left == '[' && c != ']') return false;
				if(left == '{' && c != '}') return false;
						
			}
		}
		
		return stack.isEmpty();
	}
	
	/**
	 * ����һ
	 * @param s
	 * @return
	 */
	public boolean isValid1(String s) {

		while(s.contains("[]")
				|| s.contains("{}")
				|| s.contains("()")) {
			
			s = s.replace("{}", "");
			s = s.replace("()", "");
			s = s.replace("[]", "");
			
		}
		
		return s.isEmpty();
    }
}
