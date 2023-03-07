// 页面初始化绑定事件
$(function(){
	
	// 给登录a标签绑定事件
	$("#longin").click(function(){
	
	$("#staticBackdrop").attr("id","staticBackdrop");
		// 调用登录验证函数
		login();
		
	});
	
	// 用户名输入框焦点事件
	$("#txtUserName").blur(function(){
		
		// 判断用户名是否为空
		if(isEmpty(name)){
			
			// 设置模态框内容
			$("#title").text("用户名不能为空！");
			$("#dvinfo").text("请重新输入！");
			
			// 结束函数调用
			return;
			
		}
		
	});
	
	// 密码输入框焦点事件
	$("#txtPassword").blur(function(){
		
		// 判断密码是否为空
		if(isEmpty(paw)){
			
			// 设置模态框内容
			$("#title").text("密码不能为空！");
			$("#dvinfo").text("请重新输入！");
			
			// 结束函数调用
			return;
			
		}
		
	});

});

function login(){
	
	// 获取用户名
	var name = $("#txtUserName").val();

	// 获取用户密码
	var paw = $("#txtPassword").val();
	
	
	// 判断用户名和密码是否在0到16个字符之间
	if((name.length <= 16 && name.length > 0) && (paw.length <=16 && paw.length > 0)){
		
		$("myform").attr("action","verify");	
		
		// 
		$("#staticBackdrop").removeAttr("id");
		
		// 结束函数调用
		return;		
		
	}
	
	// 设置模态框内容
	$("#staticBackdropLabel").text("用户名或密码长度最多为16位！");
	$("#dvinfo").text("请重新输入！");

	
}


/**
 * img图片下一张
 */
function checkImg(){
	
	// 获取图片的地址
	$("CheckedImg")
}


/**
 * 判空
 * @param {Object} obj
 */
function isEmpty(obj){
    if(typeof obj == "undefined" || obj == null || obj == ""){
        return true;
    }else{
        return false;
    }
}