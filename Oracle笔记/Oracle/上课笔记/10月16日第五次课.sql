```mysql
-- Oracle���ú���
-- max min avg count sum
select sum(1), count(1) from student;
select sum(age), count(age) from student;
-- round(Դ����,������λ��)   -- ����������
select round(123.45678,2) from dual;
-- trunc(Դ����,������λ��)   -- ������������
select trunc(123.45678,2) from dual;

-- nvl(���ʽ,���ʽΪ��ʱ��Ĭ��ֵ)
select nvl(null,sysdate) from dual;

select ename, nvl(comm,100)
from emp;

--decode(���ʽ,�ж�ֵ1,����ֵ1,�ж�ֵ2,����ֵ2,...,Ĭ��ֵ)
select ename, decode(comm,null,100,0,100,comm)
from emp;

--����<500 ���� 500��
-- case...when
-- (case when ����1 then ���ʽ��ֵ1
--      when ����2 then ���ʽ��ֵ2
--                 ...
--      else Ĭ��ֵ)
select (case
         when comm < 500 then
          500
         else
          nvl(comm,500)
       end)
  from emp;

--ͳ��ѧ�����е���Ů���ж�����
--  ��  Ů
--  2   5

select (select count(1) from student where sex = '��') ��,
       (select count(1) from student where sex = 'Ů') Ů
  from dual;

select sum(decode(sex, '��', 1, 0)) ��, sum(decode(sex, 'Ů', 1, 0)) Ů
  from student;

select count(decode(sex, '��', 1, null)) ��,
       sum(decode(sex, 'Ů', 1, null)) Ů
  from student;


-- Oracle������һ���з���ֵ���������в���

-- ������غ���
--lpad , rpad  (����λ�� ���) '**ab' 'abcd' 'a***'
select lpad('ab',4,'*'),rpad('c',4,'*') from dual;

--rtrim, ltrim, trim  -- ��ҵ'   a  b cd   '
select ltrim('   a  b cd   '),
       rtrim('   a  b cd   '),
       trim('   a  b cd   ') 
   from dual;

--replace(Դ�ַ�����old�ַ�����new�ַ���)
select replace('12��45��ɽ���ϻ�','��','��') from dual;

--length(�ַ���) -- ȡ�ַ����ĳ���
select length('������������') from dual;

--upper()  lower()
select upper('hello WORLD'), lower('hello WORLD') from dual;

select * from emp where upper(ename) like '%' || upper('s') || '%';

--�ַ���ƴ�� ||
select 'a' || 'b' from dual;
select ename || ':' || sal from emp;

--instr()  �����ַ�����λ��(oracle�ַ���λ�ô�1��ʼ)
select instr('123123123','3',1,2) from dual;

--substr()�ַ�����ȡ
select substr('2020-10-16',9) from dual;
select substr('2020-10-16',6,2) from dual;
select substr('2020-10-16',1,4) from dual;

-- 18970895969 => 189****5969
select substr('18970895969', 1, 3) ||
       '****' || substr('18970895969', 8)
  from dual;

-- ATM ���֣�A*  AB*  ABC*
-- ��ѯԱ��������нˮ������������Ҫ����ʾ
select substr(ename,1,length(ename)-1) || '*'
from emp;


-- to_date(���������ַ���,���ڸ�ʽ�ַ���)
-- yyyy-mm-dd hh:mi:ss  hhĬ��Ϊ12Сʱ��  hh24

-- to_char() --�����������ͣ���ֵ����
-- �������������﷨��to_char(�������͵�ֵ�����ڸ�ʽ�ַ���)
-- ������
-- ������
select to_char(sysdate,'day') from dual;
select to_char(sysdate,'month') from dual;
select to_char(sysdate,'year') from dual;

--�������������﷨��to_char(��ֵ���͵�ֵ����ֵ��ʽ�ַ���)
select to_char(123456.789, '99999999.99') from dual;
select to_char(123456.789, '00000000.00') from dual;
select to_char(0.123, 'U99999990.99') from dual;
select to_char(12034500006.789, '9999999999999.99') from dual;

-- to_number(�ַ�������,��ֵ����)

-- round()--�������������  trunc()--��������������

-- decode��������ֵ�жϣ�
-- decode(Դ����,��ֵ1,���1,��ֵ2,���2,...��ֵn,���n,Ĭ��ֵ)

--ͳ��ѧ�����е���Ů���ж�����
--  ��  Ů
--  2   5

-- case when

--��ѧ���� --abs   mod
-- sqrt


```


