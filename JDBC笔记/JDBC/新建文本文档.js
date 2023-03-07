// 判断name
function ifname() {
  var name = document.getElementById("UserName").value;
  var reg = /^\w{4,12}$/;
  if (!reg.test(name)) {
    alert("只能为英文字母，数字或者下划线，长度为4-16个字符");
    return false;
  }
  return true;
}
// 判断第一次密码和第二次密码
function ifpws() {
  var valuepws1 = document.getElementById("password1").value;
  var valuepws2 = document.getElementById("password2").value;
  var reg = /^[a-zA-Z]\w{5,15}$/;
  if (!reg.test(valuepws1)) {
    alert("密码只能为6-16个字符组成字母或数字组成且字母开头");
    return false;
  }
  if (valuepws1 != valuepws2) {
    alert("密码并不相等");
    return false;
  }
  return true;
}
// 出生日期
function ifdate_of_birth() {
  var date = document.getElementById("date").value;
  var reg = /^\d{4}-\d{1,2}-\d{1,2}/;
  if (!reg.test(date)) {
    alert("出生日期格式不正确");
    return false;
  }
  return true;
}
// 电子邮件
function ifemail() {
  var email = document.getElementById("email").value;
  var reg = /^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
  if (!reg.test(email)) {
    alert("电子邮箱格式不正确");
    return false;
  }
  return true;
}

// 地区选择
function region() {
  var num = document.getElementById("national").value;
  // 当点击其他地区的时候
  if (num == "2") {
    document.getElementById("china").style.display = "none";
    document.getElementById("foregn").style.display = "block";
  }
  if (num == "1") {
    document.getElementById("china").style.display = "block";
    document.getElementById("foregn").style.display = "none";
  }
}
// 地区是否为请选择
function ifregion() {
  var china = document.getElementById("china");
  var foregn = document.getElementById("foregn");
  var c1;
  var c2;
  for (i = 0; i < china.length; i++) { //下拉框的长度就是它的选项数.
    if (china[i].selected == true) {
      c1 = china[i].value; //获取当前选择项的值.
    }
  }
  for (i = 0; i < foregn.length; i++) { //下拉框的长度就是它的选项数.
    if (foregn[i].selected == true) {
      c2 = china[i].value; //获取当前选择项的值.
    }
  }
  if (c1 == 0 && c2 == 0) {
    alert("请选择地区!!")
    return false;
  }
  return true;

}

// 提交
function but() {
  if (ifname() && ifdate_of_birth() && ifpws() && ifregion() && ifemail()) {
    return true;
  }
  return false;
}

function list(){
    var one = documnet.forms["myform"]["national"].value;
    var distr = document.forms["myform"]["distr"];
    var distract = document.forms["myform"]["distract"];
    if(one == 1){
     
      distr.style.display = "none";
      distract.style.display = "inline"
    }
    if (one == 2) {
      distract.style.display = "none"
      distr.style.display = "none";
    }

}


function lists(){
  
}