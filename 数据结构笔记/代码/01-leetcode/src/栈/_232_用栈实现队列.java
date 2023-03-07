package ջ;

import java.util.Stack;

/**
 * https://leetcode-cn.com/problems/implement-queue-using-stacks/
 * ����˼·��
 * 	1��׼������ջ��inStack outStack
 *  2�����ʱpush��inStack��
 *  3������ʱ
 *  	���outStackΪ�գ���inStack������Ԫ��push��outStack�У�outStack�ٵ���ջ��Ԫ��
 *  	���outStack��Ϊ�գ�outStack����ջ��Ԫ��
 * @author ҹ����
 *
 */
public class _232_��ջʵ�ֶ��� {
	
	// ���ȴ�������ջ�����ڴ洢����
	Stack<Integer> inStack;
	Stack<Integer> outStack;

	/**
	 * ���캯����������
	 */
    public _232_��ջʵ�ֶ���() {
    	inStack = new Stack<>();
    	outStack = new Stack<>();
    }
    
    /**
     * ���
     * @param x
     */
    public void push(int x) {

    	inStack.push(x);
    }
    
    /**
     * ����
     * @return
     */
    public int pop() {
    	checkOutStack();
    	return outStack.pop();
    }
    
    /**
     * ��ȡջ��Ԫ��
     * @return
     */
    public int peek() {
    	checkOutStack();
    	return outStack.peek();
    }
    
    /**
     * �Ƿ�Ϊ��
     * @return
     */
    public boolean empty() {
    	return inStack.isEmpty() && outStack.isEmpty();
    }
    
    
    private void checkOutStack() {
		// �ж�outStact�Ƿ�Ϊ��
    	if(outStack.isEmpty()) {
    		// �����Ϊ�ս�inStack�е�Ԫ��ȫ��push����outStack��
    		while (!inStack.isEmpty()) {
				
    			outStack.push(inStack.pop());
			}
    	}
	}
}
