<?php
require_once "lib.php";

if(isset($_GET['action'])){
	require_once(__DIR__."/".$_GET['action'].".php");
}
else{
	if($_SESSION['login']==1){
		echo "<script>window.location.href='./index.php?action=update'</script>";
	}
	else{
		echo "<script>window.location.href='./index.php?action=login'</script>";
	}
}
