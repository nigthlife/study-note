/**
 * 
 */
package top.vicon.Task;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

/**
 * @author ����Ƽ 2020��10��27�� ����5:12:49 ����JBDC_TaskOne.java
 *
 */
public class JBDC_TaskOne {
    static Scanner input = new Scanner(System.in);
    public static void main(String[] args) {
	meun();	//����˵�
	int indexNumber = 0;  //�����û���������
	
	Connection con = null;
	Statement st = null;
	try {
	    // ��������
	    Class.forName("oracle.jdbc.OracleDriver");
	    //��������	                   
	    con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl","java2019","888888");	  
	    //����statement�����û�ִ��SQLָ��
	    st = con.createStatement();    
	    //
	    while (true) {
		System.out.print("�����룺");
		indexNumber = input.nextInt();
		switch (indexNumber) {

		case 1:
		    Insert(st);  //��������
		    break;
		case 2:
		    Update(st);  //��������
		    break;
		case 3:
		    Delete(st);	 //ɾ������
		    break;
		case 4:
		    Select(st);  //��ѯ����
		    break;
		default:
		    System.out.println("��������ȷ������");
		}
	    }
	    
	} catch (Exception e) {
	    e.printStackTrace();
	}finally {
	    
	    try {
		if(st != null) {
		    st.close();
		}
	    } catch (SQLException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	    }
	}

    }
    public static void meun() {
	System.out.println("1.����ѧ����Ϣ");
	System.out.println("2.�޸�ѧ����Ϣ");
	System.out.println("3.ɾ��ѧ����Ϣ");
	System.out.println("4.��ѯѧ����Ϣ");
	
    }
    //��ѯ����
    public static void Select(Statement st) {
	
	ResultSet rs = null;
	try {
	    rs = st.executeQuery("select stuid,stuno,\"name\",age,sex from student");
	    
	    while(rs.next()) {
		System.out.println(rs.getInt("stuid") +"\t"+ rs.getString("stuno") +"\t"+ rs.getString("name")+
			"\t"+rs.getInt("age") +"\t"+ rs.getString("sex"));
	    }   
	    
	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}finally {
	    
	    try {
		if(rs != null) {
		    rs.close();
		}
	    } catch (SQLException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	    }
	}
	
    }
    //ɾ������
    public static void Delete(Statement st) {
	
	try {
	    int row = st.executeUpdate("delete from student where stuno = 'S005'");
	    System.out.println("ɾ��"+row+"���ݳɹ���");
	    
	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
    }
    //��������
    public static void Update(Statement st) {
	
	try {
	    int row = st.executeUpdate("update student set age = 22 where \"name\" = '����'");
	    System.out.println("����" + row + "����");
	}catch(SQLException e) {
	    e.printStackTrace();
	}
    }

    // ����һ����Ϣ
    public static void Insert(Statement st) {

	String name = null;
	int No = 0;
	String studentNo = null;
	int age = 0;
	String sex = null;
	System.out.print("��������:");
	No = input.nextInt();
	System.out.print("������ѧ��:");
	studentNo = input.next();
	System.out.print("����������:");
	name = input.next();
	System.out.print("����������:");
	age = input.nextInt();
	System.out.print("�������Ա�:");
	sex = input.next();
	String insert = "insert into student values(" + No + "," + "'" + studentNo + "'" + "," + "'" + name + "'" + ","
		+ age + "," + "'" + sex + "'" + ")";
	try {
	    int row = st.executeUpdate(insert);
	    System.out.println("����" + row + "���ݳɹ�!");

	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}catch(Exception e) {
	    e.printStackTrace();
	}
    }
}
