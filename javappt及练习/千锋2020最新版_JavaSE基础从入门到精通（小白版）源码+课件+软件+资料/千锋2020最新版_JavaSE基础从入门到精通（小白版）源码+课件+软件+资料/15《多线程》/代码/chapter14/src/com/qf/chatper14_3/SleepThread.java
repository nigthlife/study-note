package com.qf.chatper14_3;
/**
 * 线程类
 * @author wgy
 *
 */
public class SleepThread extends Thread{
	@Override
	public void run() {
		for(int i=0;i<10;i++) {
			System.out.println(Thread.currentThread().getName()+"......."+i);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
