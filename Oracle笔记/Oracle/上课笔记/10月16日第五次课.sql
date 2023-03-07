```mysql
-- Oracle常用函数
-- max min avg count sum
select sum(1), count(1) from student;
select sum(age), count(age) from student;
-- round(源数据,保留的位数)   -- 会四舍五入
select round(123.45678,2) from dual;
-- trunc(源数据,保留的位数)   -- 不会四舍五入
select trunc(123.45678,2) from dual;

-- nvl(表达式,表达式为空时的默认值)
select nvl(null,sysdate) from dual;

select ename, nvl(comm,100)
from emp;

--decode(表达式,判断值1,返回值1,判断值2,返回值2,...,默认值)
select ename, decode(comm,null,100,0,100,comm)
from emp;

--奖金<500 都按 500发
-- case...when
-- (case when 条件1 then 表达式的值1
--      when 条件2 then 表达式的值2
--                 ...
--      else 默认值)
select (case
         when comm < 500 then
          500
         else
          nvl(comm,500)
       end)
  from emp;

--统计学生表中的男女各有多少人
--  男  女
--  2   5

select (select count(1) from student where sex = '男') 男,
       (select count(1) from student where sex = '女') 女
  from dual;

select sum(decode(sex, '男', 1, 0)) 男, sum(decode(sex, '女', 1, 0)) 女
  from student;

select count(decode(sex, '男', 1, null)) 男,
       sum(decode(sex, '女', 1, null)) 女
  from student;


-- Oracle函数：一定有返回值，基本都有参数

-- 日期相关函数
--lpad , rpad  (不足位数 填充) '**ab' 'abcd' 'a***'
select lpad('ab',4,'*'),rpad('c',4,'*') from dual;

--rtrim, ltrim, trim  -- 作业'   a  b cd   '
select ltrim('   a  b cd   '),
       rtrim('   a  b cd   '),
       trim('   a  b cd   ') 
   from dual;

--replace(源字符串，old字符串，new字符串)
select replace('12老45上山打老虎','老','猛') from dual;

--length(字符串) -- 取字符串的长度
select length('用良心做教育') from dual;

--upper()  lower()
select upper('hello WORLD'), lower('hello WORLD') from dual;

select * from emp where upper(ename) like '%' || upper('s') || '%';

--字符串拼接 ||
select 'a' || 'b' from dual;
select ename || ':' || sal from emp;

--instr()  查找字符串的位置(oracle字符的位置从1开始)
select instr('123123123','3',1,2) from dual;

--substr()字符串截取
select substr('2020-10-16',9) from dual;
select substr('2020-10-16',6,2) from dual;
select substr('2020-10-16',1,4) from dual;

-- 18970895969 => 189****5969
select substr('18970895969', 1, 3) ||
       '****' || substr('18970895969', 8)
  from dual;

-- ATM 名字：A*  AB*  ABC*
-- 查询员的姓名和薪水，姓名按以上要求显示
select substr(ename,1,length(ename)-1) || '*'
from emp;


-- to_date(日期类型字符串,日期格式字符串)
-- yyyy-mm-dd hh:mi:ss  hh默认为12小时制  hh24

-- to_char() --处理日期类型，数值类型
-- 处理日期类型语法：to_char(日期类型的值，日期格式字符串)
-- 其它：
-- 求星期
select to_char(sysdate,'day') from dual;
select to_char(sysdate,'month') from dual;
select to_char(sysdate,'year') from dual;

--处理日期类型语法：to_char(数值类型的值，数值格式字符串)
select to_char(123456.789, '99999999.99') from dual;
select to_char(123456.789, '00000000.00') from dual;
select to_char(0.123, 'U99999990.99') from dual;
select to_char(12034500006.789, '9999999999999.99') from dual;

-- to_number(字符串类型,数值类型)

-- round()--会进行四舍五入  trunc()--不进行四舍五入

-- decode函数（等值判断）
-- decode(源数据,等值1,结果1,等值2,结果2,...等值n,结果n,默认值)

--统计学生表中的男女各有多少人
--  男  女
--  2   5

-- case when

--数学函数 --abs   mod
-- sqrt


```


