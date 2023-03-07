
// 页面加载完毕绑定事件
$(function(){

	// 给下拉列表绑定ajax异步请求事件事件
	$("#exampleFormControlSelect1").click(function(){

		console.log("开始绑定事件...");

		$.ajax({
			url:"taskServlet",
			type:"post",
			data:{"op":"select","usId":$(this).val()},
			dataType: "json",
			success: function(result){

				// 判断操作是否失败
				if ("operation failed" == result) {

					console.log("操作失败！");

				}else{

					// 调用拼接表函数
					SplicedTable(result);
				}

			}
		});

	});

	// 给删除按钮绑定事件


	// 给保存按钮添加事件
	$("#save").click(function(){


	});

});

// 拼接table中的内容
function SplicedTable(result){

	// 用于拼接表内容
	let strHtml = "";

	// 循环拼接表单
	for(let i = 0; i < result.length; i++){

		strHtml = strHtml + "<tr>" +
		 "<td>" + result[i].taskName +"</td>" +
         "<td>" + result[i].taskName + "</td>" +
         "<td>" + result[i].taskState + "</td>" +
         "<td><a href=\"#\" class=\"btn btn-warning\">删除</a>" +
         "<a href=\"#\" class=\"btn btn-warning\">编辑</a>" +
         "<a href="+ms[i].taskid+"></a></td>" +
		 "</tr>"
	}

	// 将拼接完的内容添加进入表单中
	$("#tbodyInfo").html(strHtml);

	// 给拼接后的删除按钮绑定事件
	BindDel();

	// 给拼接后的编辑按钮绑定事件
	BindEdit();

}

// 给删除按钮绑定事件
function BindDel(){

	$("#tbInfo tr:gt(0)").find("td:last a:first").click(function(){

		// 判断是否删除
		if(confirm("是否需要删除当前行数据？")){

			// 删除一行
			DeleteRow(this);
		}

	});
}

// 给编辑按钮绑定事件
function BindEdit(){

	$("#tbInfo tr:gt(0)").find("td:last a:eq(1)").click(function(){

		// 弹出模态框
		Modify(this);

	});

}

/**
 * 功能：实现删除一行数据
 * @param obj
 */
function DeleteRow(id){

	// 获取任务id
	var taskId = $(id).next().attr("href");

	$.ajax({
		url:"taskServlet",
		type:"post",

	});

}

// 给编辑按钮添加事件
function Modify(cuuent){

	// 弹出模态框
	$('#exampleModal').modal('show');


	// 获取当前任务的名称、任务详、任务状态
	var taskName = $(cuuent).parent().parent().find("td:first").text();	
	var taskInfo = $(cuuent).parent().parent().find("td:eq(1)").text();				  
	var taskStatus = $(cuuent).parent().parent().find("td:eq()").text();

	// 获取当前选中用户名称
	var selectUsName = $("#exampleFormControlSelect2").val();

	// 用户列表异步请求
	$.ajax({
		url:"taskServlet",
		type:"post",
		data:{"op":"select","usId":"UsIdAll"},
		dataType: "json",
		success: function(result){

			// 判断操作是否失败！
			if("operation failed" == result){



			}else{

				// 拼接字符串变量
				var strHt = "<option> -- 请选择 --</option>";

				// 将拆分的字符串依次写入下拉列表中
				for(let i = 0 ; i < AllusId.length; i++){
									
					trHt = strHt + "<option value='" + AllusId[i].usId + "'>" + AllusId[i].usName + "<option>"
				}

				// 将拼接完的内容添加进入select下拉列表中
				$("#exampleFormControlSelect1").html(strHt);

				// 设置模态框中下拉列表选中用户为主页面选中用户
				$("#exampleFormControlSelect1").val($("#exampleFormControlSelect2").val());

			}


		}

	// 将获取的任务名称、任务状态、任务详情填入表单中
	$("#exampleFormControlInput1").val(taskName);
	$("#exampleFormControlTextarea1").val(taskInfo);
	$("#ipStatus").val(taskStatus);

	// 去除不可选择属性
	$("#ipStatus").removeAttr("disabled");

	
}

// 异步刷新页面表单内容
function Refresh(){

	$.ajax({
			url:"taskServlet",
			type:"post",
			data:{"op":"select","usId":$("#exampleFormControlSelect2").val()},
			dataType: "json",
			success: function(result){

				// 判断操作是否失败
				if ("operation failed" == result) {

					console.log("操作失败！");

				}else{

					// 调用拼接表函数
					SplicedTable(result);
				}

			}
		});

}