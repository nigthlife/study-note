package com.qf.chatper14_3;
/**
 * 优先级
 * @author wgy
 *
 */
public class PriorityThread extends Thread{
	@Override
	public void run() {
		for(int i=0;i<50;i++) {
			System.out.println(Thread.currentThread().getName()+"============"+i);
		}
	}
}
