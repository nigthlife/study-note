// Decompiled by Jad v1.5.8e2. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://kpdus.tripod.com/jad.html
// Decompiler options: packimports(3) fieldsfirst ansi space 
// Source File Name:   B.java

package com.qf.inheritance_4;

import java.io.PrintStream;

// Referenced classes of package com.qf.inheritance_4:
//			A

public class B extends A
{

	int num3;

	public B()
	{
		super(10, 20);
		num3 = 100;
		System.out.println("B��Ĭ�Ϲ��췽��");
	}

	public void m2()
	{
		System.out.println("B�е�m2����");
	}
}
