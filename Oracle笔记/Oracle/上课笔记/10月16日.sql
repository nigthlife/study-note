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
select instr('123123123','7',1,2) from dual;

-- 查询员工姓名包含 ‘M’的员工信息
select * from emp where ename like '%M%';
select * from emp where instr(ename,'M') > 0;

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


--to_date(日期类型字符串,日期格式字符串)
--yyyy-mm-dd hh:mi:ss  hh默认为12小时制  hh24
-- hour minute second

select to_date('2020-10-10 10:10:00','yyyy-mm-dd hh24:mi:ss') from dual;

insert into emp (empno,ename,hiredate) 
values ('2222','dateTest',to_date('2020-10-10','yyyy-mm-dd'));

select * from emp where empno = '2222';

--to_char() 
--处理日期类型语法：to_char(日期类型的值，日期格式字符串)
--处理日期类型  2020-10
select ename,to_char(hiredate,'yyyy"年"mm"月"') from emp where empno = '2222';


-- 求星期
select to_char(sysdate,'day') from dual;
select to_char(sysdate,'month') from dual;
select to_char(sysdate,'year') from dual;

-- 日期之间的运算
select sysdate - 1 from dual;

--处理数值类型语法：to_char(数值类型的值，数值格式字符串)
select to_char(123456.789, '99999999.99') from dual;
select to_char(123456.789, '00000000.00') from dual;
select to_char(0.123, 'U99999990.99') from dual;
select to_char(12034500006.789, '9999999999999.99') from dual;

-- 查询员工姓名和薪水(保留一位小数);
select * from emp for update;
create table c_n
(
   cid number,
   mon number
)

insert into c_n values (1,11);
insert into c_n  values (1,11.1);
insert into c_n  values (1,88.88);
insert into c_n  values (1,999.999);
insert into c_n  values (1,0.88);
insert into c_n  values (1,0.08);
commit;

select * from c_n;

select ltrim(to_char(mon,'$99999990.99')) from c_n;

--to_number(字符串类型,数值类型)

-- 88 * 2 + 1 =>

select round(to_number('88.89'),1) * 2 + 1 from dual;

--round()--会进行四舍五入  trunc()--不进行四舍五入

--decode函数（等值判断）
--decode(源数据,等值1,结果1,等值2,结果2,...等值n,结果n,默认值)

--统计学生表中的男女各有多少人
--  男  女
--  2   5

-- case when

--数学函数 --abs   mod
-- sqrt
select abs(-1) from dual;

-- Oracle数据库编程
begin
   dbms_output.put_line('hello Oracle');
end;

-- 1:变量的定义
-- declare 变量名 数据类型;
declare
v_name varchar2(50);
v_age number(3);
v_sal emp.sal%type;

--2:变量的赋值
--2.1:定义变量时赋值
declare 
v_name varchar2(50) := '张三';
v_age number(3);
begin
   -- 定义后，在代码块中赋值
   v_age := 20;
   dbms_output.put_line(v_age || v_name);
end;

-- select into 给变量赋值
-- select 表达式, ... into 变量名, ... from 数据源 where ...
declare 
v_count number;
begin
   select count(1) into v_count from emp where sal > 1000;
  
   dbms_output.put_line(v_count);
end;


--3:变量的使用
-- 变量只能在begin end代码块之内使用

-- 条件判断语句
-- if 条件表达式 then [begin] 代码 [end] end if;
-- if 条件表达式 then 代码  elsif 条件表达式 then 代码 end if;
-- if 条件表达式 then 代码  elsif 条件表达式 then 代码 else 代码 end if;

declare 
v_count number;
begin
   
   v_count := &c;
   
   if v_count > 0 then
       dbms_output.put_line('它是大于0的');
   elsif v_count > -10 then
       dbms_output.put_line(v_count || '是大于-10小于0的');
   else
       dbms_output.put_line('它是小于等于-10的');
   end if;
   
end;

-- 预习（要有预习的笔记-重点查）
-- case when   end case;
-- while 条件表达式  loop  循环体  end loop;
-- for(隐式游标) for ... in ...
-- 函数
-- 存储过程
-- 事务
-- 异常处理
-- 视图
-- 索引
-- 触发器
-- 同义词
-- ...........




