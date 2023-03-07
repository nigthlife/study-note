--1��ѯ�����ŵ����нˮ�����нˮ��ƽ��нˮ
-- round(ԭ����,����С��λ��) -- ������������
-- trunc(ԭ����,����С��λ��) -- ��������������
select max(sal),min(sal),round(avg(sal),2)
  from emp
  group by deptno;

--2��ѯ��SMITH�����쵼����
select ename
  from emp
 where empno = (select mgr 
                  from emp 
                 where ename = 'SMITH')

select (select ename from emp ee where ee.empno = e.mgr)
  from emp e
 where ename = 'SMITH';
 
--3��ѯ��˾��нˮ��ߵ�Ա����Ϣ 
select * from emp where sal = (select max(sal) from emp);

--4��ѯ�����ŵ�ƽ��нˮ�����ű�ţ��������ơ�
-- �������ӵı�ʾ����  +�Ŷ���������
select d.deptno, d.dname, avg(sal)
  from emp e, dept d
 where e.deptno(+) = d.deptno
 group by d.deptno, d.dname;

--5��ѯ����λ�����нˮ�����нˮ��Ҫ��ֻͳ��нˮ>1000��

--6��ѯнˮ���ڸò���ƽ��нˮ��Ա����Ϣ
select *
  from emp e
 where sal > (select avg(sal) from emp ee where ee.deptno = e.deptno);

--7����ʹ�÷��麯������ѯнˮ�����ֵ(˼��һ��any or all)
select sal from emp where sal >= all (select sal from emp);

--8��ѯԱ��н�ʴ���������1200�Ĳ��ű�źͲ�������
select distinct d.deptno,d.dname
from emp e join dept d on e.deptno = d.deptno
where e.sal < 1200

-- exists:
-- SQL�Ż�������exists�Ͳ�Ҫ��in
select d.deptno, d.dname
  from dept d
 where exists (select 1
          from emp e
         where e.deptno = d.deptno
           and e.sal < 1200);


--1:group by ������
--ͳ��ÿ�����Ÿ�ְλ���ܹ���
select deptno,job,sum(sal) from emp
group by rollup(deptno,job);

--2:������(���ʺ������,ƽ������ϵ����)
-- ��ѯԱ����Ա�����ϼ���Ϣ
select e.ename,boss.ename
from emp e left join emp boss
on e.mgr = boss.empno;

--3:��β�ѯ(�������Ƕ�һ�ű�)
--connect by .����. start with .��ʼ����.
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


-- DDL(���ݶ�������)
-- create alter drop

-- ��ռ䣺
create tablespace wxg_tablespace
datafile 'C:\app\Administrator\oradata\orcl\WXG.DBF'
size 100M;

-- �û�

-- ��Ȩ

-- α�� rownum  rowid-- ����ID
-- ��ѯԱ������Ϣ��ֻ��ʾǰ������Ϣ
select rownum, emp.* from emp where rownum < 4;

-- ��ѯнˮ��ߵ�ǰ����Ա����Ϣ��
select rownum, t.*
  from (select rownum, empno, ename, sal 
          from emp 
        order by sal desc) t
   where rownum < 4;

-- ��������
-- �ַ�������
-- char: char(����)   char(10)   'abc       '  
-- varchar2: varchar2(����) varc har2(100)  'a����ʡ'  <=4000
-- nchar, nvarchar2: ָ��Unicode�������洢����:  <=2000
--                   �����ַ������������ֽ�������
-- char, nvarchar2

-- ����������: clob, blob

-- ����ֵ���ͣ�number
-- number(38)
-- age number(3)  12 555  1000����
-- score number(5,2)   12.345  123.45  123.4

-- �������ͣ�date  'yyyy-mm-dd hh24:mi:ss'

/* create table ����(��Ŀ����_ģ������_ҵ�����)
   (
       ���� �������� [Լ��],
       ���� �������� [Լ��],
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

-- ɾ����drop table ����

-- �����: 
alter table bankcard
add cardtype nvarchar2(20);
--���ݳ�ʼ��
update bankcard set cardtype = '����'; 
commit;

-- ����DDL�Զ��ύ��DML�ֶ��ύ

select * from bankCard;
select * from user_tab_cols where table_name = 'BANKCARD';

-- DML insert update delete select
insert into bankCard
  (cardNo, idCard, "name", pwd, money, createDate)
values
  ('6227002031666788968', '360121199901012221', '����','888888', 10000, sysdate);
insert into bankCard
  (cardNo, idCard, "name", pwd, money, createDate)
values
  ('6227002031666782221', '360121199901012233', '����','888888', 10000, sysdate);

select * from bankCard;

--DML:insert(ָ����) ɾ��ȫ�����ݣ�delete <-> truncate
--Լ��:primary key,  foreign key, unique, not null, check, default 
-- �������ʱ�����
-- �޸ı�ṹ��ʽ���

-- Ӳ����ҵ����ѯ

