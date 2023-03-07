--1查询各部门的最高薪水、最低薪水、平均薪水
-- round(原数据,保留小数位数) -- 进行四舍五入
-- trunc(原数据,保留小数位数) -- 不进行四舍五入
select max(sal),min(sal),round(avg(sal),2)
  from emp
  group by deptno;

--2查询‘SMITH’的领导姓名
select ename
  from emp
 where empno = (select mgr 
                  from emp 
                 where ename = 'SMITH')

select (select ename from emp ee where ee.empno = e.mgr)
  from emp e
 where ename = 'SMITH';
 
--3查询公司中薪水最高的员工信息 
select * from emp where sal = (select max(sal) from emp);

--4查询各部门的平均薪水及部门编号，部门名称。
-- 左右连接的表示方法  +号对面的是左表
select d.deptno, d.dname, avg(sal)
  from emp e, dept d
 where e.deptno(+) = d.deptno
 group by d.deptno, d.dname;

--5查询各岗位的最高薪水，最低薪水。要求只统计薪水>1000的

--6查询薪水大于该部门平均薪水的员工信息
select *
  from emp e
 where sal > (select avg(sal) from emp ee where ee.deptno = e.deptno);

--7不能使用分组函数，查询薪水的最高值(思考一下any or all)
select sal from emp where sal >= all (select sal from emp);

--8查询员工薪资待遇有少于1200的部门编号和部门名称
select distinct d.deptno,d.dname
from emp e join dept d on e.deptno = d.deptno
where e.sal < 1200

-- exists:
-- SQL优化：能用exists就不要用in
select d.deptno, d.dname
  from dept d
 where exists (select 1
          from emp e
         where e.deptno = d.deptno
           and e.sal < 1200);


--1:group by 升级版
--统计每个部门各职位的总工资
select deptno,job,sum(sal) from emp
group by rollup(deptno,job);

--2:自连接(不适合做大表,平方级关系，慢)
-- 查询员工和员工的上级信息
select e.ename,boss.ename
from emp e left join emp boss
on e.mgr = boss.empno;

--3:层次查询(本质上是对一张表)
--connect by .条件. start with .起始条件.
select e.empno,e.ename,e.mgr
from emp e
start with e.mgr is null
connect by prior e.empno = e.mgr;

-- 把级别查出来，按级别排序
select level,e.empno,e.ename,e.mgr
from emp e
start with e.mgr is null
connect by prior e.empno = e.mgr
order by level;

-- 查询编号为7788的上级(含上上级)信息
select e.empno,e.ename,e.mgr
from emp e
start with e.empno = '7788'
connect by  e.empno = prior e.mgr


-- DDL(数据定义语言)
-- create alter drop

-- 表空间：
create tablespace wxg_tablespace
datafile 'C:\app\Administrator\oradata\orcl\WXG.DBF'
size 100M;

-- 用户

-- 授权

-- 伪列 rownum  rowid-- 物理ID
-- 查询员工表信息，只显示前三条信息
select rownum, emp.* from emp where rownum < 4;

-- 查询薪水最高的前三个员工信息。
select rownum, t.*
  from (select rownum, empno, ename, sal 
          from emp 
        order by sal desc) t
   where rownum < 4;

-- 数据类型
-- 字符串类型
-- char: char(长度)   char(10)   'abc       '  
-- varchar2: varchar2(长度) varc har2(100)  'a江西省'  <=4000
-- nchar, nvarchar2: 指定Unicode编码来存储数据:  <=2000
--                   所有字符都是用两个字节来保存
-- char, nvarchar2

-- 大数据类型: clob, blob

-- 数据值类型：number
-- number(38)
-- age number(3)  12 555  1000不行
-- score number(5,2)   12.345  123.45  123.4

-- 日期类型：date  'yyyy-mm-dd hh24:mi:ss'

/* create table 表名(项目名称_模块名称_业务表名)
   (
       列名 数据类型 [约束],
       列名 数据类型 [约束],
       .....
   );
*/

create table bankCard
(
    cardNo char(19),
    idCard char(18),
    "name" nvarchar2(100),
    pwd char(6),
    money  number(18,2),
    createDate date
);

-- 删除表：drop table 表名

-- 添加列: 
alter table bankcard
add cardtype nvarchar2(20);
--数据初始化
update bankcard set cardtype = '龙卡'; 
commit;

-- 事务：DDL自动提交，DML手动提交

select * from bankCard;
select * from user_tab_cols where table_name = 'BANKCARD';

-- DML insert update delete select
insert into bankCard
  (cardNo, idCard, "name", pwd, money, createDate)
values
  ('6227002031666788968', '360121199901012221', '张三','888888', 10000, sysdate);
insert into bankCard
  (cardNo, idCard, "name", pwd, money, createDate)
values
  ('6227002031666782221', '360121199901012233', '李四','888888', 10000, sysdate);

select * from bankCard;

--DML:insert(指插入) 删除全表数据：delete <-> truncate
--约束:primary key,  foreign key, unique, not null, check, default 
-- 创建表的时候添加
-- 修改表结构方式添加

-- 硬性作业：查询

