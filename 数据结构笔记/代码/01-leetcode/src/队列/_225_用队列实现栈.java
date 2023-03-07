package ����;

import java.util.ArrayDeque;


/**
 * https://leetcode-cn.com/problems/implement-stack-using-queues/
 * @author ҹ����
 *
 */
public class _225_�ö���ʵ��ջ {
	
	private ArrayDeque<Integer> arrayDeque;
	

    public _225_�ö���ʵ��ջ() {
    	arrayDeque = new ArrayDeque<>();
    }
    
    /**
     * ��ջ
     * @param x
     */
    public void push(int x) {
    	arrayDeque.addLast(x);
    }
    
    /**
     * ��ջ
     * @return
     */
    public int pop() {
    	return arrayDeque.pollLast();
    }
    
    /**
     * ջ��
     * @return
     */
    public int top() {
    	return arrayDeque.getLast();
    }
    
    /**
     * ջ�Ƿ�Ϊ��
     * @return
     */
    public boolean empty() {
    	return arrayDeque.isEmpty();
    }
}
