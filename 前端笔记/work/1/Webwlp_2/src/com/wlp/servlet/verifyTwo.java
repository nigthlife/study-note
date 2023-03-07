package com.wlp.servlet;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class verifyTwo
 */
@WebServlet("/verifyTwo")
public class verifyTwo extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public verifyTwo() {
	super();
	// TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
	    throws ServletException, IOException {

	this.doPost(request, response);// ����doPost����
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

	// �����ַ���
	res.setContentType("text/html;charset=gbk");
	res.setContentType("text/html");

	// ��Referer�ж��Ƿ�ӵ���֮��ҳ���˳��ģ��������cookie��ֵ����������������Ϊ0
	if ("http://localhost:8080/Webwlp_2/varify".equals(req.getHeader("referer"))) {

	    // ��ȡcookie��ֵ
	    Cookie[] cookies = req.getCookies();

	    // �ж�cookies��ֵ��Ϊ��
	    if (cookies != null && cookies.length != 0) {

		// ��cookie��ֵ����Ϊ��
		for (int i = 0; i < cookies.length; i++) {

		    if (cookies[i].getName().equals("name")) {

			cookies[i] = new Cookie("name", null);// ɾ��cookie

			cookies[i].setMaxAge(0); // ������������Ϊ0

			res.addCookie(cookies[i]); // �������cookie

		    } else if (cookies[i].getName().equals("password")) {

			cookies[i] = new Cookie("password", null);// ɾ��cookie

			cookies[i].setMaxAge(0); // ������������Ϊ0

			res.addCookie(cookies[i]); // �������cookie
		    }
		}
	    }

	}

	// ��ȡ��¼����ҳ��ķ�������ʵ·��
	String path = req.getSession().getServletContext().getRealPath("MyProjectLogin.html");

	// ����һ���ı���
	FileInputStream fs = new FileInputStream(path);

	// ��ȡHTML�ַ���
	BufferedReader br = new BufferedReader(new InputStreamReader(fs));

	// �洢html�ַ���
	StringBuilder sb = new StringBuilder();

	// ��ʱ����
	String htmlText = null;

	// ���HTML�ı��ַ�������
	while ((htmlText = br.readLine()) != null) {

	    sb.append(htmlText);

	}

	// ����HTML�ļ�����
	htmlText = sb.toString();

	// ��Ӧҳ��
	res.getWriter().append(htmlText);

	// ��ȡcookie
	Cookie[] cs = req.getCookies();

	// �ж��ǲ�����Ч��cookie
	if (cs != null && cs.length != 0) {

	    String cookieName = null;
	    String cookiePwd = null;

	    for (Cookie c : cs) {

		if (c.getName().equals("name")) {

		    // �õ��û���
		    cookieName = c.getValue();

		}
		if (c.getName().equals("pass")) {

		    // �õ�����
		    cookiePwd = c.getValue();
		}
	    }

	    // �ж��û��������붼����Ϊ��
	    if (cookieName != null && cookiePwd != null) {

		// �����������뷢��LoginServlet2 ������֤,�����֤�ɹ�����ת����½���ҳ��,����������
		res.sendRedirect("transpondLogin?name=" + cookieName + "&password=" + cookiePwd);

	    }
	}

    }

}
