-- 每周一穿职业装（下周一开始实行）
-- 作业
--15查询10号部门的员工在整个公司中所占的比例

-- Oracle虚表 dual
-- sysdate系统日期
-- SQL优化的问题：索引列（不要使用函数或其它运算去处理再作为条件）

select deptno, round((select count(1) from emp where deptno = 10) 
                      / (select count(1) from emp), 4) * 100.00 || '%' as percentAge
from emp where deptno = 10 
group by deptno

select 10,
       round((select count(1) from emp where deptno = 10) /
             (select count(1) from emp),
             4) * 100.00 || '%'
  from dual;

select 10 * 10 from dual;
--12查询所有81年之后入职的员工信息 
select * from emp;
select * from emp where hiredate > to_date('1981-12-31 23:59:59','yyyy-mm-dd hh24:mi:ss');
select sysdate from dual; 
select to_char(sysdate,'yyyy') from dual;  


-- 系统表：
select * from where tablename = 'emp'
--select * from tab where table_name = 'EMP';
select * from user_tab_columns where table_name='EMP';
select * from user_cons_columns cl where table_name = 'EMP';


-- 查询：多表查询


--关联关系1：1，1：n; m:n  E-R
emp    dept

-- 等值连接
-- 不等值连接
-- 内连接
-- 外连接
-- 查询所有员工姓名，部门名称
select *
from emp e,dept d
where e.deptno = d.deptno;

-- 查询每个员工它的薪水是哪个级别（员工名称，薪水，级别）
select * from emp;
select * from salgrade;

select ename,sal,grade
from emp e, salgrade g
where e.sal >= g.losal and e.sal <= g.hisal;

-- 查询所有员工姓名，部门名称
select ename,dname
from emp e inner join dept d 
on e.deptno = d.deptno
where d.dname like '%C%';

select ename,dname
from emp e inner join dept d 
on e.deptno = d.deptno and d.dname like '%C%';
-- 找个例子（）

-- 左外连接 右外连接  全外连接
-- left join  right join

--统计所有部门的员工数量
select dname, count(1) total
from emp e, dept d
where e.deptno = d.deptno
group by d.deptno, d.dname;
select count(1) from dept;

select d.deptno, count(e.deptno) total
from dept d left join emp e 
  on d.deptno = e.deptno
 group by d.deptno

select * from dept;

-- count(*,1,列名,distinct 列名)  
--count(列名) 不统计列名为空的行
-- 统计有奖金的员工数量
select count(1) from emp where comm > 0;
select sum(decode(comm,null,0,0,0,1)) from emp;

--count(distinct 列名) 不统计列名为空的行
-- 统计员工岗位的种类数量
select count(distinct job) from emp;
select * from emp;

-- full join  = 左连接 并 右连接
select * from emp e full join dept d 
on e.deptno = d.deptno;

-- group by 分组
select d.dname count(1) total
from emp e, dept d
where e.deptno = d.deptno
group by d.deptno, d.dname;

select e.ename, d.deptno, d.dname
from emp e ,dept d
where e.deptno = d.deptno

-- SQL优化：尽量少用集合运算
-- union 联合去重（并集） 
-- union all 联合不去重（并集不去重）, 
-- minus 差集
-- intersect 交集
-- 注：列名和列的数量必须一样，数据类型必须兼容

select ename
  from emp
 where sal < 2000
   and ename != 'WARD'
union
select ename
  from emp
 where job = 'SALESMAN';
 
 select ename
  from emp
 where sal < 2000
   and ename != 'WARD'
union all
select ename
  from emp
 where job = 'SALESMAN';

 select ename
  from emp
 where sal < 2000
   and ename != 'WARD'
minus
select ename
  from emp
 where job = 'SALESMAN';

 select ename
  from emp
 where sal < 2000
   and ename != 'WARD'
intersect
select ename
  from emp
 where job = 'SALESMAN';

-- 子查询: select (...) from (...) where (...) group by (不能使用子查询)
--         having(...)
-- exist:
-- 查询有员工的部门编号和名称
-- 查询没有员的部门编号和名称

select myDname
  from (select (select dname from dept d where e.deptno = d.deptno) myDname
          from emp e)
 group by myDname;










delete from emp where deptno is null;
commit; -- 事务







select * from emp;






