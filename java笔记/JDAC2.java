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
 * @author 武乐萍 2020年10月27日 下午5:12:49 类名JBDC_TaskOne.java
 *
 */
public class JBDC_TaskOne {
    static Scanner input = new Scanner(System.in);
    public static void main(String[] args) {
	meun();	//输出菜单
	int indexNumber = 0;  //接收用户输入数字
	
	Connection con = null;
	Statement st = null;
	try {
	    // 加载驱动
	    Class.forName("oracle.jdbc.OracleDriver");
	    //创建连接	                   
	    con = DriverManager.getConnection("jdbc:oracle:thin:@127.0.0.1:1521:orcl","java2019","888888");	  
	    //创建statement对象，用户执行SQL指令
	    st = con.createStatement();    
	    //
	    while (true) {
		System.out.print("请输入：");
		indexNumber = input.nextInt();
		switch (indexNumber) {

		case 1:
		    Insert(st);  //插入数据
		    break;
		case 2:
		    Update(st);  //更新数据
		    break;
		case 3:
		    Delete(st);	 //删除数据
		    break;
		case 4:
		    Select(st);  //查询数据
		    break;
		default:
		    System.out.println("请输入正确的数字");
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
	System.out.println("1.插入学生信息");
	System.out.println("2.修改学生信息");
	System.out.println("3.删除学生信息");
	System.out.println("4.查询学生信息");
	
    }
    //查询数据
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
    //删除数据
    public static void Delete(Statement st) {
	
	try {
	    int row = st.executeUpdate("delete from student where stuno = 'S005'");
	    System.out.println("删除"+row+"数据成功！");
	    
	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
    }
    //更新数据
    public static void Update(Statement st) {
	
	try {
	    int row = st.executeUpdate("update student set age = 22 where \"name\" = '张三'");
	    System.out.println("更新" + row + "数据");
	}catch(SQLException e) {
	    e.printStackTrace();
	}
    }

    // 插入一条信息
    public static void Insert(Statement st) {

	String name = null;
	int No = 0;
	String studentNo = null;
	int age = 0;
	String sex = null;
	System.out.print("请输入编号:");
	No = input.nextInt();
	System.out.print("请输入学号:");
	studentNo = input.next();
	System.out.print("请输入姓名:");
	name = input.next();
	System.out.print("请输入年龄:");
	age = input.nextInt();
	System.out.print("请输入性别:");
	sex = input.next();
	String insert = "insert into student values(" + No + "," + "'" + studentNo + "'" + "," + "'" + name + "'" + ","
		+ age + "," + "'" + sex + "'" + ")";
	try {
	    int row = st.executeUpdate(insert);
	    System.out.println("插入" + row + "数据成功!");

	} catch (SQLException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}catch(Exception e) {
	    e.printStackTrace();
	}
    }
}
