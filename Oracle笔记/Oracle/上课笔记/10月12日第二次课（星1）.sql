-- ÿ��һ��ְҵװ������һ��ʼʵ�У�
-- ��ҵ
--15��ѯ10�Ų��ŵ�Ա����������˾����ռ�ı���

-- Oracle��� dual
-- sysdateϵͳ����
-- SQL�Ż������⣺�����У���Ҫʹ�ú�������������ȥ��������Ϊ������

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
--12��ѯ����81��֮����ְ��Ա����Ϣ 
select * from emp;
select * from emp where hiredate > to_date('1981-12-31 23:59:59','yyyy-mm-dd hh24:mi:ss');
select sysdate from dual; 
select to_char(sysdate,'yyyy') from dual;  


-- ϵͳ��
select * from where tablename = 'emp'
--select * from tab where table_name = 'EMP';
select * from user_tab_columns where table_name='EMP';
select * from user_cons_columns cl where table_name = 'EMP';


-- ��ѯ������ѯ


--������ϵ1��1��1��n; m:n  E-R
emp    dept

-- ��ֵ����
-- ����ֵ����
-- ������
-- ������
-- ��ѯ����Ա����������������
select *
from emp e,dept d
where e.deptno = d.deptno;

-- ��ѯÿ��Ա������нˮ���ĸ�����Ա�����ƣ�нˮ������
select * from emp;
select * from salgrade;

select ename,sal,grade
from emp e, salgrade g
where e.sal >= g.losal and e.sal <= g.hisal;

-- ��ѯ����Ա����������������
select ename,dname
from emp e inner join dept d 
on e.deptno = d.deptno
where d.dname like '%C%';

select ename,dname
from emp e inner join dept d 
on e.deptno = d.deptno and d.dname like '%C%';
-- �Ҹ����ӣ���

-- �������� ��������  ȫ������
-- left join  right join

--ͳ�����в��ŵ�Ա������
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

-- count(*,1,����,distinct ����)  
--count(����) ��ͳ������Ϊ�յ���
-- ͳ���н����Ա������
select count(1) from emp where comm > 0;
select sum(decode(comm,null,0,0,0,1)) from emp;

--count(distinct ����) ��ͳ������Ϊ�յ���
-- ͳ��Ա����λ����������
select count(distinct job) from emp;
select * from emp;

-- full join  = ������ �� ������
select * from emp e full join dept d 
on e.deptno = d.deptno;

-- group by ����
select d.dname count(1) total
from emp e, dept d
where e.deptno = d.deptno
group by d.deptno, d.dname;

select e.ename, d.deptno, d.dname
from emp e ,dept d
where e.deptno = d.deptno

-- SQL�Ż����������ü�������
-- union ����ȥ�أ������� 
-- union all ���ϲ�ȥ�أ�������ȥ�أ�, 
-- minus �
-- intersect ����
-- ע���������е���������һ�����������ͱ������

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

-- �Ӳ�ѯ: select (...) from (...) where (...) group by (����ʹ���Ӳ�ѯ)
--         having(...)
-- exist:
-- ��ѯ��Ա���Ĳ��ű�ź�����
-- ��ѯû��Ա�Ĳ��ű�ź�����

select myDname
  from (select (select dname from dept d where e.deptno = d.deptno) myDname
          from emp e)
 group by myDname;










delete from emp where deptno is null;
commit; -- ����







select * from emp;






