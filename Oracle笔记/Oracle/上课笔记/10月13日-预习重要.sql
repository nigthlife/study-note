--1:group by ������
--ͳ��ÿ�����Ÿ�ְλ���ܹ���
select deptno,job,sum(sal) from emp
group by rollup(deptno,job);
rollup()��group by��һ����չ�����������ĸо��ǣ����Զ���н���group by��Ȼ��ֱ����ͳ��
����ͨ��group by��ȣ�����������һ���ܵ�ͳ��


--2:������(���ʺ������,ƽ������ϵ����)
-- ��ѯԱ����Ա�����ϼ���Ϣ
select e.ename,boss.ename
from emp e left join emp boss
on e.mgr = boss.empno;

--3:��β�ѯ(�������Ƕ�һ�ű�)
--connect by  .����. start with .��ʼ����.
select e.empno,e.ename,e.mgr
from emp e
start with e.mgr is null
connect by prior e.empno = e.mgr;

-- �Ѽ�������������������
select level,e.empno,e.ename,e.mgr
from emp e
start with e.mgr is null
connect by prior e.empno = e.mgr
order by level;

-- ��ѯ���Ϊ7788���ϼ�(�����ϼ�)��Ϣ
select e.empno,e.ename,e.mgr
from emp e
start with e.empno = '7788'
connect by  e.empno = prior e.mgr


--���壺CONNECT BY PRIOR org_id = parent_id��
--����˵��һ����¼��org_id �Ǳ�����¼��parent_id��
--������¼�ĸ�������һ����¼��


-- �ҳ�Ա�����У�������ߵ�ǰ����Ա����Ϣ��rownum


-- DDL
-- ɾ���ص�:delete  turncate


-- DML

