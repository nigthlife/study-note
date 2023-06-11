<?php
error_reporting(0);
session_start();
function safe($parm)
{
    $array = array('union', 'regexp', 'load', 'into', 'flag', 'file', 'insert', "'", '\\', "*", "alter");
    return str_replace($array, 'hacker', $parm);
}
class User
{
    public $id;
    public $age = null;
    public $nickname = null;
    public function login()
    {
        if (isset($_POST['username']) && isset($_POST['password'])) {
            // 数据库对象
            $mysqli = new dbCtrl();

            $this->id = $mysqli->login('select id,password from user where username=?');
            if ($this->id) {
                $_SESSION['id'] = $this->id;
                $_SESSION['login'] = 1;
                echo "你的ID是" . $_SESSION['id'];
                echo "你好！" . $_SESSION['token'];
                echo "<script>window.location.href='./update.php'</script>";
                return $this->id;
            }
        }
    }
    public function update()
    {
        // 将返回的结果反序列化
        $Info = unserialize($this->getNewinfo());
        // 获取参数值
        $age = $Info->age;
        $nickname = $Info->nickname;
        // 创建了一个更新处理对象
        new UpdateHelper($_SESSION['id'], $Info, "update user SET age=$age,nickname=$nickname where id=" . $_SESSION['id']);
        //这个功能还没有写完 先占坑
    }
    public function getNewInfo()
    {
        $age = $_POST['age'];
        $nickname = $_POST['nickname'];

        // 创建一个info对象，并将其序列化，序列化结果需要经过safe过滤
        return safe(serialize(new Info($age, $nickname)));
    }
    public function __destruct()
    {
        return file_get_contents($this->nickname); //危
    }
    public function __toString()
    {
        $this->nickname->update($this->age);
        return "0-0";
    }
}

class Info
{
    public $age;
    public $nickname;
    public $CtrlCase;
    public function __construct($age, $nickname)
    {
        $this->age = $age;
        $this->nickname = $nickname;
    }
    public function __call($name, $argument)
    {
        echo $this->CtrlCase->login($argument[0]);
    }
}

// 更新处理
class UpdateHelper
{
    public $id;
    public $newinfo;
    public $sql;
    public function __construct($newInfo, $sql)
    {
        $newInfo = unserialize($newInfo);
        $upDate = new dbCtrl();
    }
    // 这里可以拿到sessionid
    public function __destruct()
    {
        echo $this->sql;
    }
}

class dbCtrl
{
    public $hostname = "127.0.0.1";
    public $dbuser = "root";
    public $dbpass = "root";
    public $database = "test";
    public $name;
    public $password;
    public $mysqli;
    public $token;
    public function __construct()
    {
        $this->name = $_POST['username'];
        $this->password = $_POST['password'];
        $this->token = $_SESSION['token'];
    }
    public function login($sql)
    {
        // 获取数据库连接
        $this->mysqli = new mysqli($this->hostname, $this->dbuser, $this->dbpass, $this->database);

        if ($this->mysqli->connect_error) {
            die("连接失败，错误:" . $this->mysqli->connect_error);
        }
        // ('select id,password from user where username=?');
        $result = $this->mysqli->prepare($sql);
        $result->bind_param('s', $this->name);
        $result->execute();
        // 获取结果
        $result->bind_result($idResult, $passwordResult);
        // 拿到结果
        $result->fetch();
        $result->close();
        if ($this->token == 'admin') {
            return $idResult;
        }
        if (!$idResult) {
            echo ('用户不存在!');
            return false;
        }
        if (md5($this->password) !== $passwordResult) {
            echo ('密码错误！');
            return false;
        }
        $_SESSION['token'] = $this->name;
        return $idResult;
    }
    public function update($sql)
    {
        //还没来得及写
    }
}
