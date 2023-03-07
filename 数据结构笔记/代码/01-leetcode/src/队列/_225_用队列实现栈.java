package 队列;

import java.util.ArrayDeque;


/**
 * https://leetcode-cn.com/problems/implement-stack-using-queues/
 * @author 夜生情
 *
 */
public class _225_用队列实现栈 {
	
	private ArrayDeque<Integer> arrayDeque;
	

    public _225_用队列实现栈() {
    	arrayDeque = new ArrayDeque<>();
    }
    
    /**
     * 入栈
     * @param x
     */
    public void push(int x) {
    	arrayDeque.addLast(x);
    }
    
    /**
     * 出栈
     * @return
     */
    public int pop() {
    	return arrayDeque.pollLast();
    }
    
    /**
     * 栈顶
     * @return
     */
    public int top() {
    	return arrayDeque.getLast();
    }
    
    /**
     * 栈是否为空
     * @return
     */
    public boolean empty() {
    	return arrayDeque.isEmpty();
    }
}
