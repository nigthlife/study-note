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

	// ��ȡsession����
	HttpSession session = req.getSession();

	// ��ȡ����
	String usName = (String) session.getAttribute("name");

	String usPaw = (String) session.getAttribute("pass");

	

	// ��ȡ����������ʵ·��
	String realPath = req.getSession().getServletContext().getRealPath("MyProject.html");

	FileInputStream fs = new FileInputStream(realPath);

	BufferedReader br = new BufferedReader(new InputStreamReader(fs));

	// �洢��Ӧ�ַ���
	StringBuilder sb = new StringBuilder();

	// ��ʱ����
	String htmlText = null;

	// ���HTML�ı��ַ�������
	while ((htmlText = br.readLine()) != null) {

	    sb.append(htmlText);

	}

	// ����HTML�ļ�����
	htmlText = sb.toString();

//	System.out.println(htmlText);

	// �滻�ı��е��û���

	if (usName != null) {

	    htmlText = htmlText.replace("{$userName}", usName);

	} else {

	    htmlText = htmlText.replace("{$userName}", req.getParameter("user"));

	}

	int id = 0;

	// �����û����������ȡid
	if (usName != null && usPaw != null) {

	    id = new server().selectUserId(usName, usPaw);

	} else {

	    id = new server().selectUserId(req.getParameter("user"), req.getParameter("pass"));
	}

	// ��ȡ���û�������
	List<task> tasks = new server().selectOne(id);

	System.out.println("size=>" + tasks.size());

	// �ж��Ƿ��ѯ������
	if (tasks.size() != 0) {

	    // ��������ҳ��
	    StringBuilder content = new StringBuilder();

	    // �����û�������
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

	    // ������д���ı�������
	    htmlText = htmlText.replace("{$content}", content);

	}

	// ��Ӧҳ��
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
     * // ��ȡ��¼����ҳ��ķ�������ʵ·�� String path =
     * req.getSession().getServletContext().getRealPath("middle.html");
     * 
     * // ����һ���ı��� FileInputStream fs = new FileInputStream(path);
     * 
     * // ��ȡHTML�ַ��� BufferedReader br = new BufferedReader(new
     * InputStreamReader(fs));
     * 
     * 
     * // �洢html�ַ��� StringBuilder sb = new StringBuilder();
     * 
     * // ��ʱ���� String htmlText = null;
     * 
     * // ���HTML�ı��ַ������� while ((htmlText = br.readLine()) != null) {
     * 
     * sb.append(htmlText);
     * 
     * }
     * 
     * // ����HTML�ļ����� htmlText = sb.toString();
     * 
     * // ��Ӧҳ�� res.getWriter().append(htmlText);
     * 
     * 
     * // String address = "http://127.0.0.1:8080/Webwlp_2/middle.html";
     * 
     * // δ�ҵ����û�ʱ����ת�� // res.sendRedirect("/Webwlp_2/middle.html");
     * 
     * // RequestDispatcher dd = req.getRequestDispatcher(address);
     * 
     * // dd.forward(req, res);
     * 
     * }
     */

}
