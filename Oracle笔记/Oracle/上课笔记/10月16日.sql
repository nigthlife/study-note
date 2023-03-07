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
select instr('123123123','7',1,2) from dual;

-- ��ѯԱ���������� ��M����Ա����Ϣ
select * from emp where ename like '%M%';
select * from emp where instr(ename,'M') > 0;

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


--to_date(���������ַ���,���ڸ�ʽ�ַ���)
--yyyy-mm-dd hh:mi:ss  hhĬ��Ϊ12Сʱ��  hh24
-- hour minute second

select to_date('2020-10-10 10:10:00','yyyy-mm-dd hh24:mi:ss') from dual;

insert into emp (empno,ename,hiredate) 
values ('2222','dateTest',to_date('2020-10-10','yyyy-mm-dd'));

select * from emp where empno = '2222';

--to_char() 
--�������������﷨��to_char(�������͵�ֵ�����ڸ�ʽ�ַ���)
--������������  2020-10
select ename,to_char(hiredate,'yyyy"��"mm"��"') from emp where empno = '2222';


-- ������
select to_char(sysdate,'day') from dual;
select to_char(sysdate,'month') from dual;
select to_char(sysdate,'year') from dual;

-- ����֮�������
select sysdate - 1 from dual;

--������ֵ�����﷨��to_char(��ֵ���͵�ֵ����ֵ��ʽ�ַ���)
select to_char(123456.789, '99999999.99') from dual;
select to_char(123456.789, '00000000.00') from dual;
select to_char(0.123, 'U99999990.99') from dual;
select to_char(12034500006.789, '9999999999999.99') from dual;

-- ��ѯԱ��������нˮ(����һλС��);
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

--to_number(�ַ�������,��ֵ����)

-- 88 * 2 + 1 =>

select round(to_number('88.89'),1) * 2 + 1 from dual;

--round()--�������������  trunc()--��������������

--decode��������ֵ�жϣ�
--decode(Դ����,��ֵ1,���1,��ֵ2,���2,...��ֵn,���n,Ĭ��ֵ)

--ͳ��ѧ�����е���Ů���ж�����
--  ��  Ů
--  2   5

-- case when

--��ѧ���� --abs   mod
-- sqrt
select abs(-1) from dual;

-- Oracle���ݿ���
begin
   dbms_output.put_line('hello Oracle');
end;

-- 1:�����Ķ���
-- declare ������ ��������;
declare
v_name varchar2(50);
v_age number(3);
v_sal emp.sal%type;

--2:�����ĸ�ֵ
--2.1:�������ʱ��ֵ
declare 
v_name varchar2(50) := '����';
v_age number(3);
begin
   -- ������ڴ�����и�ֵ
   v_age := 20;
   dbms_output.put_line(v_age || v_name);
end;

-- select into ��������ֵ
-- select ���ʽ, ... into ������, ... from ����Դ where ...
declare 
v_count number;
begin
   select count(1) into v_count from emp where sal > 1000;
  
   dbms_output.put_line(v_count);
end;


--3:������ʹ��
-- ����ֻ����begin end�����֮��ʹ��

-- �����ж����
-- if �������ʽ then [begin] ���� [end] end if;
-- if �������ʽ then ����  elsif �������ʽ then ���� end if;
-- if �������ʽ then ����  elsif �������ʽ then ���� else ���� end if;

declare 
v_count number;
begin
   
   v_count := &c;
   
   if v_count > 0 then
       dbms_output.put_line('���Ǵ���0��');
   elsif v_count > -10 then
       dbms_output.put_line(v_count || '�Ǵ���-10С��0��');
   else
       dbms_output.put_line('����С�ڵ���-10��');
   end if;
   
end;

-- Ԥϰ��Ҫ��Ԥϰ�ıʼ�-�ص�飩
-- case when   end case;
-- while �������ʽ  loop  ѭ����  end loop;
-- for(��ʽ�α�) for ... in ...
-- ����
-- �洢����
-- ����
-- �쳣����
-- ��ͼ
-- ����
-- ������
-- ͬ���
-- ...........




