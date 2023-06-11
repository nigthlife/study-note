<?php
highlight_file(__FILE__);

class night
{
    public $night;

    public function __destruct(){
        echo $this->night . '哒咩哟';
    }
}

class day
{
    public $day;

    public function __toString(){
        echo $this->day->go();
    }

    public function __call($a, $b){
        echo $this->day->getFlag();
    }
}


class light
{
    public $light;

    public function __invoke(){
        echo $this->light->d();
    }
}

class dark
{
    public $dark;

    public function go(){
        ($this->dark)();
    }

    public function getFlag(){
        include(hacked($this->dark));
    }
}

function hacked($s) {
    if(substr($s, 0,1) == '/'){
        die('呆jio步');
    }
    $s = preg_replace('/\.\.*/', '.', $s);
    $s = urldecode($s);
    $s = htmlentities($s, ENT_QUOTES, 'UTF-8');
    return strip_tags($s);
}


$un = unserialize($_POST['‮⁦快给我传参⁩⁦pop']); // 
throw new Exception('seino');
