package com.wlp.servlet;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.wlp.Bean.task;
import com.wlp.servers.server;

/**
 * Servlet implementation class verify
 */
@WebServlet("/verify")
public class verify extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * Default constructor.
     */
    public verify() {
	// TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
	// TODO Auto-generated method stub

	res.setContentType("text/html;charset=gbk");

	// 获取session对象
	HttpSession session = req.getSession();

	// 获取姓名
	String usName = (String) session.getAttribute("name");

	String usPaw = (String) session.getAttribute("pass");

	

	// 获取服务器的真实路径
	String realPath = req.getSession().getServletContext().getRealPath("MyProject.html");

	FileInputStream fs = new FileInputStream(realPath);

	BufferedReader br = new BufferedReader(new InputStreamReader(fs));

	// 存储响应字符串
	StringBuilder sb = new StringBuilder();

	// 临时变量
	String htmlText = null;

	// 获得HTML文本字符串内容
	while ((htmlText = br.readLine()) != null) {

	    sb.append(htmlText);

	}

	// 最终HTML文件内容
	htmlText = sb.toString();

//	System.out.println(htmlText);

	// 替换文本中的用户名

	if (usName != null) {

	    htmlText = htmlText.replace("{$userName}", usName);

	} else {

	    htmlText = htmlText.replace("{$userName}", req.getParameter("user"));

	}

	int id = 0;

	// 根据用户名和密码获取id
	if (usName != null && usPaw != null) {

	    id = new server().selectUserId(usName, usPaw);

	} else {

	    id = new server().selectUserId(req.getParameter("user"), req.getParameter("pass"));
	}

	// 获取该用户的任务
	List<task> tasks = new server().selectOne(id);

	System.out.println("size=>" + tasks.size());

	// 判断是否查询到数据
	if (tasks.size() != 0) {

	    // 保存内容页面
	    StringBuilder content = new StringBuilder();

	    // 遍历用户的任务
	    for (task task : tasks) {

		content.append("<tr>");
		content.append("<td scope=\"col\"><input type=\"hidden\" value=\"").append(task.getTaskid())
			.append("\">").append(task.getTaskName()).append("</td>");
		content.append(
			"<td scope=\"col\"><div class=\"task\" data-toggle=\"modal\" data-target=\"#exampleModal\">")
			.append(task.getTaskDetail()).append("</div></td>");
		content.append("<td scope=\"col\">").append(task.getTaskState()).append("</td>");
		content.append("<td scope=\"col\">").append(task.getCreateDate()).append("</td>");
		content.append("</tr>");
	    }

	    // 将内容写入文本内容中
	    htmlText = htmlText.replace("{$content}", content);

	}

	// 响应页面
	res.getWriter().append(htmlText);
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
	// TODO Auto-generated method stub
	doGet(req,res);
    }
    /*
     * else {
     * 
     * // 获取登录错误页面的服务器真实路径 String path =
     * req.getSession().getServletContext().getRealPath("middle.html");
     * 
     * // 创建一个文本流 FileInputStream fs = new FileInputStream(path);
     * 
     * // 获取HTML字符流 BufferedReader br = new BufferedReader(new
     * InputStreamReader(fs));
     * 
     * 
     * // 存储html字符串 StringBuilder sb = new StringBuilder();
     * 
     * // 临时变量 String htmlText = null;
     * 
     * // 获得HTML文本字符串内容 while ((htmlText = br.readLine()) != null) {
     * 
     * sb.append(htmlText);
     * 
     * }
     * 
     * // 最终HTML文件内容 htmlText = sb.toString();
     * 
     * // 响应页面 res.getWriter().append(htmlText);
     * 
     * 
     * // String address = "http://127.0.0.1:8080/Webwlp_2/middle.html";
     * 
     * // 未找到该用户时进行转发 // res.sendRedirect("/Webwlp_2/middle.html");
     * 
     * // RequestDispatcher dd = req.getRequestDispatcher(address);
     * 
     * // dd.forward(req, res);
     * 
     * }
     */

}
