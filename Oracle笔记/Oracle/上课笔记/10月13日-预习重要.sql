--1:group by 升级版
--统计每个部门各职位的总工资
select deptno,job,sum(sal) from emp
group by rollup(deptno,job);
rollup()是group by的一个扩展函数，初步的感觉是，可以多个列进行group by，然后分别进行统计
跟普通的group by相比，就是最后多了一个总的统计


--2:自连接(不适合做大表,平方级关系，慢)
-- 查询员工和员工的上级信息
select e.ename,boss.ename
from emp e left join emp boss
on e.mgr = boss.empno;

--3:层次查询(本质上是对一张表)
--connect by  .条件. start with .起始条件.
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


--意义：CONNECT BY PRIOR org_id = parent_id；
--就是说上一条记录的org_id 是本条记录的parent_id，
--即本记录的父亲是上一条记录。


-- 找出员工表中，工次最高的前三名员工信息。rownum


-- DDL
-- 删除重点:delete  turncate


-- DML

