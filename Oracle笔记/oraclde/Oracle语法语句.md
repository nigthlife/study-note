#目录

[^我了个乖乖]:

------

[TOC]







[Mysql语法](https://blog.csdn.net/weixin_49343190/article/details/107313699?utm_source=app)

------



## 1.Oracle中常见的数据类型

### 字符串

```mysql
-- varchar2(length):可变长的字符串,length定义最长字符串的字节数.
length最大值位4000,节省空间,查询效率低

-- char(length):定长的字符串,length定义最长的字符串的字节数,最大值2000
浪费空间,查询效率高

varchar(length):等价于varchar2(length),varchar2是Oracle独有的. 
```

### [数字类型](#目录)

```mysql
number(p,s):p表示定义数字的长度(不包含小数点),s表示小数点后面的尾数
定义商品的价格 number(5,2),表示小数点前面有3个数字,后面有两个数字
123.23  12.23(合法,在精度里面)  1234.10(不合法) 

number:表示描述整数 
```

### [日期类型](#目录)

```mysql
date:七个字节,如果是英文环境 DD-MOR-RR "11-JUN-15" 
如果是中文环境 15-7月-15
yyyy = 年份 
mm = 月份 
dd = 日 
hh(24) = 时(24小时制) 
mi = 分 
ss = 秒
```

------



## 2.使用alter修改表结构

##### [添加字段](#目录)

```mysql
alter  table 表名 add （新的字段 字段类型，....）;
例：想在t_temp表中追加字段
alter table t_temp add(deptno number(11));
-- 案例
alter table emp add sex char(1) default('0') not null;
```

##### [删除字段](#目录)

```mysql
alter table 表名 drop column 字段名
例：删除t_temp表中的gender字段
alter table t_temp drop column gender;
```

##### [修改列名](#目录)

```mysql
alter table 表名 rename column 旧表名 to 新表名；
例：将t_temp表中的deptno修改为 dept_no
alter table t_temp rename column deptno to dept_no;
```

##### [修改字段类型](#目录)

```mysql
alter table 表名 modify (列名 新类型,...);
例：将t_temp表的salary的类型修改为number(5,2)
alter table t_temp modify (salary number(5,2));
```

------



##  3.[truncate删除表中的数据](#目录)

#### truncate

```mysql
truncate table 表名
truncate 只是清空表中的数据，但是保留表的结构
drop 将表结构删除
```

------



## 4.DML语句：[操作表数据](#目录)

#### 4.1 插入数据 insert into

```mysql
insert into 表名 [(字段名)] values(值....)
如果是向表中的所有字段添加数据时，可以省略字段名
例：向t-temp表中插入数据
insert into t_emp(id,name,salary,birth,job,dept_no)
values(1001,'yves',123.23,sysdate,'开发',10);
-- 开发中推荐使用明确字段名，以方便维护
```

#### 4.2删除数据delete

```mysql
delete from 表名 [where 过滤条件];
delete from t_temp;  将表中的数据全部删除
```

##### 4.2.1 [delete 和truncate的区别](#目录)

```mysql
delete属于DML（操作）语句，需要事务的支持
truncate属于DDL（定义）语句，无需事务的支持
delete逐行删除，truncate先摧毁再创建
delete需要回滚内存空间（可恢复），truncate无需回滚内存空间（不可恢复）
delete删除会产生碎片，truncate不会产生
delete性能要低于truncate
delete保留高水位线，truncate删除高水位线

DML语句需要事务管理
	commit提交数据
	rollback回滚数据
```

#### 4.3[修改记录](#目录)

```mysql
update 表名 set 字段名 = 值 [,...][where 过滤条件];
例：将id=1001的用户名改为 jerry,工资改为 888
update t_emp set name='jerry',salary=888 where id=1001;
```

------



##5.[事务控制语句](#目录)

#### （配合DML语句一起使用）

```mysql
-- 原子性（atomicity） （不可再分）
-- 隔离性 (比如共享资源，一个一个来)
-- 持久性 () 事务完成之后，对系统的影响是永久的，不可会回滚
-- 一致性

commit:提交事务
rollback:事务回滚
savepoint 事务保存点
start transaction 开启事务 


例：
		create table temp( id number);  
    insert into temp values(1);
    insert into temp values(2);
    savepoint A;								--设置事务的保存点
    insert into temp values(3);
    insert into temp values(4);
    insert into temp values(5);
    savepoint B;
    insert into temp values(6);
    insert into temp values(7);
    savepoint C;
    insert into temp values(8);
    rollback to B;							--回滚到保存点B,数据到5
    rollback to A;							--可以成功,数据到2
    rollback to C 							--报错,事务已经到了A, B、C不存在了
```

------



## 6.函数

#### 6.1[coalesce函数](#目录)

```plsql
coalesce（参数列表）：返回参数列表中第一个非空参数，最后一个参数通常为常量

例：年终提成
 如果员工的comm不为空，发comm
 如果员工的comm为空，发工资的一半
 如果sal和comm为空，发100安慰
 
   select ename,sal,comm,
   coalesce(comm,sal*0.5,100) comms
   from emp;  
```

#### 6.2[case when函数](#目录)

```mysql
-- 简单case函数
case sex 
when '1' then '男'
when '2' then '女'
else '其他' end

-- case搜索函数
case 
when sex = '1' then '男'
when sex = '2' then '女'
else '其他' end
```

##### 6.2.1[select case when 用法](#目录)

```mysql
-- 查询男生数和女生数
select grade,count(case when sex = 1 then 1 else null end) 男生数,
						count(case when sex = 2 then 1 else null end) 女生数
						from stuents group by grade;
```

##### 6.2.2[where case when 用法](#目录)

```mysql

SELECT T2.*, T1.*
   FROM T1, T2
  WHERE (CASE WHEN T2.COMPARE_TYPE = 'A' AND
                   T1.SOME_TYPE LIKE 'NOTHING%'
                THEN 1
              WHEN T2.COMPARE_TYPE != 'A' AND
                   T1.SOME_TYPE NOT LIKE 'NOTHING%'
                THEN 1
              ELSE 0

```

#### 6.2.3[简单case](#目录)

```mysql
语法:
   case exp when comexp then returnvalue
            ...
            when comexp then returnvalue
            else returnvalue
    end
      
 --  case到end之间相当于一个具体的值，可以做运算，取别名，嵌套case 等等。
 --  只要把case到end当作一个运算结果的表达式就可以了。 
 select cust_last_name,
          case credit_limit when 100 then 'low'
                            when 5000 then 'high'
                            else 'medium'
          end
     from customers;
     
     
-- 搜索case语句
2.搜索case语句
语法:
    case when boolean then return value
         ...
         when boolean then return value
         else retur nvalue
     end
     
举例:
select case when id between 1 and 10 then 'low'
            when id between 20 and 30 then 'mid'
            when id between 40 and 50 then 'high'
            else 'unknow'
       end
from product;
```





#### 6.2.4[case总结](#目录)

```mysql
-- 简单case和搜索case之间的区别
1. 简单 case只能是 when后面的表达式完全匹配 case后的表达式，相当于=，所以也不能匹配null，
2. searched case 可以作为比较条件，可以使用like、！=、 between and、<、=、 is null
is not null， 比简单 case的使用更加广泛，可以完全代替case


-- 注意事项:
1.case 表达式返回的是一个确定的value，若前面的都不匹配，则返回else中的项.
2.简单case 中的表达式，when 后面的表达式类型应该全部保持一致.
3.所有的then 后面的return_value类型要保持一致.
4.对于简单case 表达式，也就是case 表达式 when…那么when null 总是取不到。也就是case 后面的表达式如果值为null，不会与when null 匹配，只会与else匹配.
5.对于searched case来说，有自动类型转换，只要条件成立就可以。
如:select case when 1='1' then 1 end from dual; 其中1='1'条件成立

值得一提的是: sql中的case语句与pl/sql中的case语句的不同之处:
前者的else不是必须的，如果没有匹配就返回null;后者的else不写，则报case_not_found异常.

--case中嵌套子查询
Case语句中可以使用子查询，但是必须返回一行，不可以是多行.
如：
select case (select count(*) as s1 from t1 where a = 1)
           when (select count(*) as s2 from t1, t2 where t1.a = t2.a and t2.a = 1) then '相等'
           else '不相等'
       end
  from dual;

```

####6.3 [if else](#目录)

```mysql
-- 一、单个IF
1、

if a=...  then
.........
end if;

2、

if a=... then
......
else
....
end if;

-- 二、多个IF

if a=..  then
......
elsif a=..  then
....
end if;     
这里中间是“ELSIF”，而不是ELSE IF 。这里需要特别注意
```

#### 6.4 [while循环](#目录)

```mysql
-- while 条件表达式  loop  循环体  end loop;

declare
  v_num number;
begin
  v_num := 1;
  while v_num < 10 loop
     dbms_output.put_line(v_num);
     v_num := v_num + 1;
  end loop;
end;
```

####6.5 [for循环](#目录)

```mysql

-- for语法： for ... in ...  loop 代码块  end loop;
-- 输出 1~100之间的数
declare
  v_num number;
begin
  for v_num in 1..100 loop
     dbms_output.put_line(v_num);
  end loop;
end;

-- for(隐式游标)遍历
-- 语法：for 临时变量 in (子查询) loop 代码块 end loop;

例：
declare 
	v_sal number := 0;
begin 
	for tep in (select sal from emp) loop
		-- 遍历每一行，可通过tmp.列名 去行中的值，做一些业务逻辑处理
	end loop；
	dbms_output.put_line(v_sal);
end;


-- for循环遍历游标
例：
create or replace procedure test() as  -- 创建存储过程
Cursor cursor is select name from student;	-- 创建游标
name varchar(20);
begin
	for name in cursor loop
		begin
			dbms_output.put_line(name);
		end;
	end loop;
end test;
```

```html
< 
cursor 可分为俩种，
      	1. shared cursor 
        2. session cursor
        >
< 游标可分为俩种：
         隐式游标：在plsql自动为DML语句或select into 语句分配的游标
         					包括只返回一条记录的查询操作
          		作用：可以通过隐式cursor的属性来了解操作的状态和结果
          					
         显示游标：在plsql 快中声明区域中显式定义的
         					用来处理返回多行记录查询的游标
          		四个步聚：
          				1.定义游标 -- Cursor [cursor Name] is;
          				2.打开游标 -- Open [cursor Name];
          				3.操作游标 -- Fetch [Cursor Name]
          				4.关闭游标 -- Close [Cursor Name]
          >
  案例：
  
```

```mysql
案例：
DECLARE
	--定义加薪比例常量
	c_manager  CONSTANT NUMBER    :=0.15;
	c_salesman  CONSTANT NUMBER    :=0.12;
	c_clerk  CONSTANT NUMBER    :=0.10;
	v_job         VARCHAR(100);		---定义职位变量
	v_empno   VARCHAR(20); 			--定义员工编号变量
	v_ename   VARCHAR(60);  		--定义员工名称变量
	CURSOR  c_emp
	IS
		SELECT jog,empno,ename
			FROM scott.emp
		FOR UPDATE;
	BEGIN
		OPEN c_emp;							--打开游标
		LOOP										--循环游标
			FETCH c_emp
				INTO v_job,v_empno,v_ename;			--提取游标数据
			EXIT WHEN c_emp%NOTFOUND;				--如果无数据可提取则退出游标
			IF v_job = 'CLERK'
			THEN									--如果为职员，加薪10%
				UPDATE scott.emp
					SET sal = sal*(1 + c_clerk)
				WHERE CURRENT OF c_emp;
			ELSIF v_job = 'SALESMAN'
			THEN									--如果为销售职员，加薪12%
				UPDATE scott.emp
					SET sal = sal*(1 +c_salesman)
				WHERE CURRENT OF c_emp; 
			ELSIF v_job = 'MANAGER'
			THEN									--如果为经理，加薪15%
				UPDATE scott.emp
					SET sal = sal*(1 + c_manager)
				WHERE CURRENT OF c_emp;
			END IF;
			DBMS_OUTPUT.put_line ('已经为员工'
									|| v_empno
									|| ':'
									|| v_ename
									|| '成功加薪'
									)；
			END LOOP;
			CLOSE c_emp;							--关闭游标
		EXCEPTION
			WHEN NO_DATA_FOUND
			THEN									--处理PL/SQL预定义异常
				DBMS_OUTPUT.put_line('没有找到员工数据');
		END;
```



![img](https://img2018.cnblogs.com/blog/1316780/201809/1316780-20180928152009519-237728172.png)

####6.6.[分页](#目录)

```mysql
/* 
	分页的目的就是控制输出结果集的大小，
	将结果尽快返回
	
	-- 分页
-- 页的大小(pageSize), 页码(pageIndex)
-- pageSize 10  ,pageIndex 3 => 起始位置和终止位置
-- 起始位置: (pageIndex - 1) * pageSize + 1  => 21
-- 终止位置: pageSize * pageIndex           => 30
*/
10
1

（1-1） * 10 +1 = 11
（11+1）- 10 - 1 =1？


select *
  from (select rownum rn, t.*
          from (查询的SQL语句) t where rownum <= 终止位置)
 where rn >= 起始位置;

-- 1: 效率高的写法
-- 无order by排序的写法（效率最高）
-- 此方法成本最低，只嵌套一层，速度最快！即使查询的数据量再大，也几乎不受影响，速度依然
例：
select * from 
				(select rownum as rowno, t.* from emp t
         where hiredate between to_date('20060501','yyyymmdd')
         and to_date ('20060731','yyyymmdd')
         and rownum <= 20) table_alias 
         where table table_alias.rowno >= 10);

-- 2: 有ORDER BY排序的写法。(效率较高)
-- 此方法随着查询范围的扩大，速度也会越来越慢
SELECT *
  FROM (SELECT tt.*, ROWNUM AS rowno
          FROM (  SELECT t.*
                   FROM emp t
                   WHERE hire_date 
                   BETWEEN TO_DATE ('20060501', 'yyyymmdd')
                   AND TO_DATE ('20060731', 'yyyymmdd')
         ORDER BY create_time DESC, emp_no) tt
         WHERE ROWNUM <= 20) table_alias
 WHERE table_alias.rowno >= 10;
 
 -- 3: 无ORDER BY排序的写法。(建议使用方法1代替)
-- 随着查询数据量的扩张，速度会越来越慢

SELECT *
  FROM (SELECT ROWNUM AS rowno, t.*
          FROM k_task t
         WHERE flight_date 
        				BETWEEN TO_DATE ('20060501', 'yyyymmdd')
        				AND TO_DATE ('20060731', 'yyyymmdd')) table_alias
 WHERE table_alias.rowno <= 20 AND table_alias.rowno >= 10;
-- TABLE_ALIAS.ROWNO  between 10 and 100;

-- 4: 有ORDER BY排序的写法.(建议使用方法2代替)
-- 随着查询范围的扩大，速度会越来越慢

SELECT *
  FROM (SELECT tt.*, ROWNUM AS rowno
          FROM (  SELECT *
                    FROM k_task t
                   WHERE flight_date 
                BETWEEN TO_DATE ('20060501', 'yyyymmdd')
                AND TO_DATE ('20060531', 'yyyymmdd')
                ORDER BY fact_up_time, flight_no) tt) table_alias
 WHERE table_alias.rowno BETWEEN 10 AND 20;
```

```mysql
/*
		rownum是在已产生数据的基础上伪生成的编号，所以
		使用rownum必须在已有的数据基础上
		因此Oracle分页才加入了多个子查询
*/

-- 1、普通查询：
select * from table_Name t order by active_count desc;

-- 2、查询第一条记录：
select *
  from (select * from table_Name order by active_count desc)
 where rownum = 1;

-- 3、查询前3条：类似Sqlserver中的TOP 3
select *
  from (select * from table_Name order by active_count desc)
 where rownum <= 3;
 
-- 4、查询第2至第3条记录：
select *
  from (select t.*, rownum as no
          from (select * from table_Name order by active_count desc) t)
 where no between 2 and 3
 
 -- 5、在TOP3条记录的基础上查询第2至第3条记录：
select *
  from (select t.*, rownum as no
          from (select * from table_Name order by active_count desc) t  where rownum <= 3 )
 where no between 2 and 3
 
 -- 6、查询第2条以后的记录：
select *
  from (select t.*, rownum as no
          from (select * from table_Name order by actve_count desc) t)
 where no >=2
 

```

6.6.1 [分页分析](#目录)

```mysql
-- 分页查询格式
	SELECT *
  FROM (SELECT a.*, ROWNUM rn
          FROM (
            SELECT * FROM table_name) a  -- 不进行翻页的原始查询语句
         WHERE ROWNUM <= 40)  -- 控制分页查询的每页范围
 WHERE rn >= 21	-- 控制分页查询的每页范围
 
 '
 	分页的目的就是控制输出结果集大小，
 '
```





#### 6.7自定义函数

#####6.7.1[创建函数](#目录)

```mysql
-- 1： 参数的模式有三种
in ： 只读模式，参数只能被引用或者读取，不能改变它的值
out： 只写模式，参数只能被赋值，不能被引用或读取
in out： 可读可写
'参数的么事可以不写，缺省为in，out和in out俩种比较少用'

create or replace function 函数名[(参数1 模式 数据类型,......) ]
return 数据类型
as			-- 可使用as或者is，在这里没有区别

  变量1 数据类型;  -- 定义局部变量（可以单个或者多个）。也可以不定义
  ......
begin
  -- 实现函数功能的PL/SQL代码。 
  ......
  exception
  -- 异常处理的PL/SQL代码。
  ......
end;

-- 标准写法
create or replace function 函数名[(参数1 模式 数据类型,......) ]
return 数据类型
as			-- 可使用as或者is，在这里没有区别
begin
  declare
  		变量1 数据类型;  -- 定义局部变量（可以单个或者多个）。也可以不定义
  		begin
  		-- 业务代码
  		end;
  end;
end;








例：创建自定义函数（maxvalue），用于比较两个数字的大小，返回较大的值
create or replace function maxvalue(val1 number,val2 number) 
return number
as
  val number;   -- 定义局部变量，存放返回值。
begin
  if (val1>val2) then    -- 判断传入参数的大小。
      val:=val1;         -- 赋值是":="，不是"="。
  else
      val:=val2;
  end if;

  return val;  -- 返回
end;
```

##### 6.7.2调用自定义函数

```mysql
-- 函数function
-- 一定要有返回值
-- create or replace function 函数名 [(参数名 参数类型,...)] return 返回值类型
-- as/is [变量名 数据类型 ...]  begin 业务代码  end;

/*
create or replace function 函数名 [(参数名 参数类型,...)] return 返回值类型
as
begin
  declare 
    变量名  数据类型,
    ...
  begin
     -- 业务代码
  end;
end;
*/


select maxvalue（10,20） from dual;
```

##### 6.7.3[自定义函数的权限](#目录)

```mysql
'
自定义函数是数据库对象，Oracle对它的权限管理方式与其它数据库对象相同
如果maxvalue函数是scott用户创建的，其它用户调用时需要加scott用户前缀
并且具备相应的权限，否则会出现错误
< ORA-00904:MAXVALUE: 标识符无效 > 报错弹出
'
```

##### 6.7.4[删除自定义函数](#目录)

```mysql
drop function 函数名；
例：
drop function maxvalue;
```

#####6.7.5[自定义函数总结](#目录)

```java
数据库的自定义函数不会像编程语言那也广泛应用，和编程语言相比
  数据库的自定义函数太多麻烦，数据库自定义的函数能做到的功能编程语言都能做到
  

```

##### 6.7.6 [ceil函数](#目录)

```plsql
-- 1、ceil函数：朝正无穷大方向取整

-- 2、用法说明：w=ceil(z)函数将输入z中的元素取整，值w为不小于本身的最小			整数。对于复数B，分别对实部和虚部取整。
'
ceil函数的作用是bai朝正无穷方向取整，即将dum/n的结果向正无穷方向取整，如m/n=3.12，则zhiceil(m/n)的结果为4。
类似的函数有如下几个：dao
fix：朝零方向取整，如fix(-1.3)=-1; fix(1.3)=1;
floor：朝负无穷方向取整，如floor(-1.3)=-2; floor(1.3)=1;
round：四舍五入到最近的整数，如round(-1.3)=-1;round(-1.52)=-2;round(1.3)=1;round(1.52)=2。
'
```



## 7.[存储过程](#目录)

#### 语法

```mysql
/*
create or replace procedure 名称(p_...) 
[(参数名 in 数据类型, 返回参数 in out 数据类型，返回参数 out 数据类型 )]
as
begin
  declare
     变量名 数据类型;
     代码块
end;
*/

create or replace procedure 存储过程名称
is
begin
null;
end;
```

```java 
行1:
　　CREATE OR REPLACE PROCEDURE 
   是一个SQL语句通知Oracle数据库去创建一个叫做skeleton存储过程, 
  	如果存在就覆盖它;
行2:
　　IS关键词表明后面将跟随一个PL/SQL体。
    
行3:
　　BEGIN关键词表明PL/SQL体的开始。
    
行4:
　　NULL PL/SQL语句表明什么事都不做，这句不能删去，
   因为PL/SQL体中至少需要有一句;
行5:
　　END关键词表明PL/SQL体的结束
```

 #### 7.2[存储过程创建语法](#目录)

```plsql
create or replace procedure 存储过程名fs(一般p打头 )[（param1 in	 type , param2 type）]
as 
变量1 类型（值范围）； -- vs_msg varchar2(4000);
变量2 类型（值范围）;
begin
select count(*) into 变量1 from 表A where 列名 = param1;
	if(判断条件) then
		 select 列名 into 变量2 from 表A where 列名 = param1;
		 dbms_output.put_line('打印信息')
	elsif(判断条件) then
			select 列名 into 变量2 form 表A where 列名 = param1；
			dbms_output.put.line('打印信息');
	elsif(判断条件) then
			Dbms_output.put.line('打印信息');
	Else
      Raise 异常名（NO_DATA_FOUND）;
    End if;
Exception	··	`````` m
    When others then
       Rollback;
End;
```

```java
'
  注意事项：
一， 存储过程参数不带取值范围，in表示传入，out表示输出
		类型可以使用任意Oracle中的合法类型。

二，  变量带取值范围，后面接分号

三，  在判断语句前最好先用count（*）函数判断是否存在该条操作记录

四，  用select 。。。into。。。给变量赋值

五，  在代码中抛异常用 raise+异常名
'
```

## 8. [异常处理](#目录)

#### 8.1自定义异常语法

```plsql
declare
	myexception exception;
begin
	if 1 <> 2 then 
		raise myexception;
	end if;
	exception
		when myexception then  -- myexception自定义异常类型
		
		 /*注：
		 raise_application_error的
		 语法为raise_application_error(erorcd in int,erortx in varchar 2)，
		 其中erorcd的值为20001到20999*/
		 
		 -- 处理，回滚，记录错误
			raise_application_error(20001,'my exception happens');
		when others then
			dbms_output.put_line(sqlcode) -- 报错行数
			dbms_output.put_line(sqlerrm) -- 报错信息
			
			reise_application_error(20001),'An error was encountered - '||SQLCODE||
			' -ERROR- '||SQLERRM);
end
```

#### 8.2[系统预定义异常](#目录)



```java
<'错误号'>					<'异常错误信息名称'>								<'说明'>
ORA-0001 				Dup_val_on_index					违反了唯一性限制
ORA-0051				Timeout-on-resource				在等待资源时发生超时
ORA-0061				Transaction-backed-out		由于发生死锁事务被撤消
ORA-1001				Invalid-CURSOR						试图使用一个无效的游标
ORA-1012				Not-logged-on							没有连接到ORACLE
ORA-1017				Login-denied							无效的用户名/口令
ORA-1403				No_data_found							SELECT INTO没有找到数据
ORA-1422				Too_many_rows							SELECT INTO 返回多行
ORA-1476				Zero-divide								试图被零除
ORA-1722				Invalid-NUMBER						转换一个数字失败
ORA-6500				Storage-error							内存不够引发的内部错误
ORA-6501				Program-error						  内部错误
ORA-6502				Value-error							  转换或截断错误
ORA-6504				Rowtype-mismatch				  宿主游标变量与 PL/SQL变量有不兼容行类型
ORA-6511				CURSOR-already-OPEN			  试图打开一个已处于打开状态的游标
ORA-6530				Access-INTO-null				  试图为null 对象的属性赋值
ORA-6531				Collection-is-null			  试图将Exists 以外的集合( collection)方法应用																			    于一个null pl/sql 表上或varray上
ORA-6532				Subscript-outside-limit		对嵌套或varray索引得引用超出声明范围以外
ORA-6533				Subscript-beyond-count		对嵌套或varray 索引得引用大于集合中元素的个数.


```



## 9.触发器

#### 9.1 [触发器语法](#目录)

```mysql
create [or replace] triggers 触发器名 
触发时间<before>或<after> 
触发事件<update>或<delete>或<insert>
on 表名
[for each row]
begin
	plsql语句
end
```

#### 9.2 [触发器概念](#目录)

```html
<触发器名： 触发器对象的名称，>
<触发时间： 指明触发器何时执行，这个值可以取>
<触发事件： 指明哪些数据库动作会触发此触发器>
<before:  表示在数据库动作之前触发器执行>
<after:	  表示在数据库动作之后触发器执行>
<insert:  数据库插入会触发>
<update:  数据库修改会触发>
<delete:  数据库删除会触发>
<表名:     数据库触发器所在的表>
<for each row: 对表的每一行触发器执行一次，如没有写，则对整个表执行一次>
```

#### 9.3 [案例](#目录)（使用触发器实现序号自增)

```plsql
-- 创建测试表
create table tab_user(
  id number(11) primary key,
  username varchar(50),
  password varchar(50)
);

-- 创建一个序列
create Sequence MY_SQL 
increment by 1
start with 1
no maxvalue nocycle cache 20;

-- 创建一个触发器
create or replace trigger MY_TGR
before insert on tab_user for each 
row 
declare 
	next_id number;
begin
	select MY_SEQ.nextval into next_id from dual;
	new.id = next_id;
end;
```

#### 9.5级联删除[（cascade）](#目录)

```mysql
-- 创建外键的时候添加
alter table emp
add constraint fk_emp_dept 
foreign key(dept) 
references dept(deptno) 
on delete cascade;

-- 或者添加on delete set null
alter table emp
add constraint fk_emp_dept foreign key(dept) 
references dept(deptno) on delete set null;

-- 使用on delete set null有一点需要注意的是，
-- 被参参照其他表的那一列必须能够被赋空，不能有not null约束，
-- 如果已经定义了not null约束，又使用了on delete set null来删除被参照的数据时，
-- 将会发生：ORA-01407: 无法更新 (”DD”.”EMP”.”DEPT”) 为 NULL的错误。
```

## 10.[视图](#目录)

####1.语法概念

```plsql

-- 创建视图
-- 安全性，独立性，简单性		
' 语法：
create or replace view 视图名称(一般v开头) as select * from 表名;
'
```

##11.索引

#### 1.[索引概念](#目录)

```plsql
  
/*
	1.数据库索引是为了提高查询速度、检索速度（双刃剑）
	2.创建唯一索引能保证数据库表中的每一行数据的唯一性
  3.索引不是越多越好，索引也需要占用资源（CPU、内存、硬盘）
  	但是当进行增删改的时候，会更新索引。因此索引越多，增删改的速度就会越慢，
  	因为有一个维护索引的过程。			
  	创建索引之前需要权衡该字段是否经常发生增删改操作，否则可能会带来负优化的问题。
  4.提高表与表之间的连接速度
  5.索引也是需要维护，数据库对齐维护，当对表中的数据增加、删除和修改的时候索引需要动态的进行维护
  6.更新频率大的表或者列，尽量少建索引
  7.索引占用的空间可能比表的数据占的空间还大，当索引多了的时候
  8.索引其实就是用空间换时间，
  
*/


create index 索引名 on 表名(列名);

-- 多列复合索引
CREATE INDEX 索引名 ON 表名(列名1, 列名2, 列名3, ...);

-- 删除索引
drop index 索引名;

-- 查看某个表中的所有索引也同样简单。
SELECT * FROM ALL_INDEXES WHERE TABLE_NAME = '表名'

-- 还可以查看某个表中建立了索引的所有列。
SELECT * FROM ALL_IND_COLUMNS WHERE TABLE_NAME = '表名'

-- 索引建立原则
/*
--  1.索引应该建立在WHERE子句中经常使用的列上。
			如果某个大表经常使用某个字段进行查询，并且检索的啊行数小于总表行数的5%，则应该考虑在该列上建立索			 引。

		2.对于两个表连接的字段，应该建立索引。

		3.如果经常在某表的一个字段上进行Order By的话，则也应该在这个列上建立索引。

		4.不应该在小表上建立索引。
*/

```

#### 2.[sql查询](#目录)

```java
-- 先生成执行计划
-- 再按执行计划运行
```

## 12[触发器](#目录)

#### 1.[概念语法](#目录)



```plsql
-- 作用：
-- 数据确认、效验数据、复杂性的安全检查、审计、备份、同步

-- 触发器的分类
-- 语句触发器：不管影响多少行，都只会执行一次[statement]
-- 行级触发器：影响多少行，就触发多少次[for each row]
--			[:old] := 代表旧的记录，更新前的记录
--			[:new] := 代表是新的记录


create [or replace] trigger 触发器名称（一般trg_开头）
before(之前) | after(在进行操作之后) 
insert | update | delete
on 表名
[ for each row]
declare
begin
	[ select 序列名 into :new from dual;]
and;
```

## 13.[同义词](#目录)

#### 1.[概念语法](#目录)

[同义词扩展](https://blog.csdn.net/qq_35893120/article/details/78803997)

```plsql
-- 提高安全性，或者隐藏一些高深技术！

create synonym prod for 用户名下的表
-- 例：
create synonym orod for wxg.product;

-- 授权
grant create synonym to 用户
```



## 14.方法

#### 1.字符串转大小写与首字母大写

>   ```sql
>   select lower('Hello') from dual;  			-- > 转小写
>   select upper('Hello') from dual;  			-- > 转大写
>   select initcap('zhou jie lun') from dua; 	-- > 首字母大写
>   
>   -- 将查询条件全部转换为小（大）写，使等号左右两边的值处于同一种状态再进行查询。
>   select last_name,salary
>   from employees
>   where lower(last_name) = lower('johnson');
>   ```
>
>   