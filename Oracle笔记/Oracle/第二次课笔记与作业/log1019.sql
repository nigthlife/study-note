-- ���ݿ���
--case when ����1 then ����1 when ����2 then ����2  ...  when ����n then ����n else ���� end case;

select (case when 1 < 2 then 1 else 2 end) from dual;

begin
  case when 1 < 2 then
    ...
    else
  end case;
end;

declare
  v_num number;
begin
  v_num := &a;
  case
    when v_num < 10 then
      dbms_output.put_line('С����');
    when v_num < 20 then
      dbms_output.put_line('С����');
    else
      dbms_output.put_line('����');
  end case;
end;

-- ������ҵ
/*�·ݣ�1-3��9-12��6�ۣ� 4-8��8.8��
����Σ�12��������£�12-50��ԭ�ۿۼ۸�50���������ۿۼ۸�������ٴ�5��
�ɻ���ԭ�ۣ�2000Ԫ
���������&age
�·ݣ�&month
--ʹ�����ַ�ʽʵ�֣�if else,  case when��
*/
declare
    v_age number(3);
    v_month number(2);
    v_price number(8,2) := 2000;
begin
    v_age := &age;
    v_month := &mon;
    
    -- ��֤���ݵ���Ч��
    

    if v_age < 12 then
      v_price := 0;
    else
       -- 50������
       if v_age > 50 then
         v_price := v_price*0.5;
       end if;
       -- �·�
       if v_month >= 4 and v_month <= 8 then
          v_price := v_price*0.88;
       else
          v_price := v_price*0.6;
       end if;
    end if;
    
    dbms_output.put_line('���Ļ�Ʊ�۸���:' || v_price || 'Ԫ��');
    
end;


-- while �������ʽ  loop  ѭ����  end loop;
declare
  v_num number;
begin
  v_num := 1;
  while v_num < 10 loop
     dbms_output.put_line(v_num);
     v_num := v_num + 1;
  end loop;
end;

-- 1�ۼ�1~100֮���ܱ�3��5������������������

-- 2����һ���ַ����м�Ŀո񣬲�����һ��'*'���滻��
--  �����ַ�����'  a b   cd  ' �����'  a*b*cd  '
--  ��дһ�δ���ʵ�֡�
declare
   v_leftsp varchar2(200);
   v_rightsp varchar2(200);
   v_str varchar2(200) := '  a  b   cd   ';
   v_result varchar2(200) := '';
   v_tmp varchar2(200);
begin
  
   --v_str := &a;
   -- ������ߵĿո�
   v_leftsp := replace(v_str, ltrim(v_str), '');
   v_rightsp := replace(v_str, rtrim(v_str), '');
   
   -- �����м�Ŀո�
   -- 1:ȥ�����߿ո񣬵õ��м���ַ���
   v_str := trim(v_str);
   
   while instr(v_str,' ') > 0 loop
       v_tmp := substr(v_str,1, instr(v_str,' ') - 1);
       v_result := v_result || v_tmp || '*';
       v_str := ltrim(substr(v_str,instr(v_str,' ')));
   end loop;
   
   v_result := v_leftsp || v_result || v_str || v_rightsp;
   
   dbms_output.put_line(v_result);
   
end;
-- for�﷨�� for ... in ...  loop �����  end loop;
-- ��� 1~100֮�����
declare
  v_num number;
begin
  for v_num in 1..100 loop
     dbms_output.put_line(v_num);
  end loop;
end;

-- for(��ʽ�α�)����
--�﷨��for ��ʱ���� in (�Ӳ�ѯ) loop ����� end loop;
-- ��emp��������һ�У�����λ��  нˮ+����
--                            <1500 ְԱ
--                            1500~3000 �鳤
--                            3000~4500 ����
--                            4500~ �ɶ�
/*
alter table emp
add station nvarchar2(20);
*/
declare
   st nvarchar2(20);
begin
  
   for tmp in (select empno,sal+nvl(comm,0) sr from emp) loop
     
       st := (case  when tmp.sr <= 1500 then 'ְԱ' 
                    when tmp.sr <= 3000 then '�鳤'
                    when tmp.sr <= 4500 then '����'
                    else '�ɶ�' end);
       update emp set station = st where empno = tmp.empno;
       
   end loop;
       commit;
end;

select * from emp;


-- ������ҵ1��
--�ڿͻ���������һ���ֶΣ������Ա�����ͣ����� level
--(���ѽ��<100 ��ͭ, 100-500֮�� ����
--500-2000֮�� �ƽ�  2000-10000֮�� �׽�
--10000-50000֮�� ��ʯ 50000����  ����)
--���ݿͻ��������ܽ������ʼ����Ա�����͡����������ϣ�


/*begin
  for i in (��ѯ���еĿͻ���Ϣ) loop
     cash = ͨ��i.cusId��ѯ��ǰ�ͻ����ѵ��ܽ��
     result = (case when cash > 100000 then '����' when cash > 100000 then '����'....end);
     ���µ�ǰ�ͻ���cusType = result;
     update customer set cusType = result where cusid = i.cusid;
  end loop;
end;
*/

-- ��ҳ
/*
-- ����һ
select *
  from (select rownum rn, s.*
          from ( ****��ѯ��SQL���**** ) s) t
 where t.rn between 3 and 4;
*/


