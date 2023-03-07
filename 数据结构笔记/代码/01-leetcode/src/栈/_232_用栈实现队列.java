package 栈;

import java.util.Stack;

/**
 * https://leetcode-cn.com/problems/implement-queue-using-stacks/
 * 解题思路：
 * 	1、准备俩个栈，inStack outStack
 *  2、入队时push到inStack中
 *  3、出队时
 *  	如果outStack为空，将inStack中所有元素push到outStack中，outStack再弹出栈顶元素
 *  	如果outStack不为空，outStack弹出栈顶元素
 * @author 夜生情
 *
 */
public class _232_用栈实现队列 {
	
	// 首先创建两个栈，用于存储数据
	Stack<Integer> inStack;
	Stack<Integer> outStack;

	/**
	 * 构造函数创建对象
	 */
    public _232_用栈实现队列() {
    	inStack = new Stack<>();
    	outStack = new Stack<>();
    }
    
    /**
     * 入队
     * @param x
     */
    public void push(int x) {

    	inStack.push(x);
    }
    
    /**
     * 出队
     * @return
     */
    public int pop() {
    	checkOutStack();
    	return outStack.pop();
    }
    
    /**
     * 获取栈顶元素
     * @return
     */
    public int peek() {
    	checkOutStack();
    	return outStack.peek();
    }
    
    /**
     * 是否为空
     * @return
     */
    public boolean empty() {
    	return inStack.isEmpty() && outStack.isEmpty();
    }
    
    
    private void checkOutStack() {
		// 判断outStact是否为空
    	if(outStack.isEmpty()) {
    		// 如果不为空将inStack中的元素全部push进入outStack中
    		while (!inStack.isEmpty()) {
				
    			outStack.push(inStack.pop());
			}
    	}
	}
}
