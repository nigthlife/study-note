package com.qf.chap17_2;
/**
 * 键盘
 * @author wgy
 *
 */
public class KeyBoard implements Usb{

	@Override
	public void service() {
		System.out.println("键盘开始工作了...");
	}

}
