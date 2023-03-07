-- 数据库编程
--case when 条件1 then 代码1 when 条件2 then 代码2  ...  when 条件n then 代码n else 代码 end case;

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
      dbms_output.put_line('小孩子');
    when v_num < 20 then
      dbms_output.put_line('小朋友');
    else
      dbms_output.put_line('大人');
  end case;
end;

-- 课堂作业
/*月份：1-3或9-12：6折， 4-8：8.8折
年龄段：12岁免费以下，12-50：原折扣价格，50岁以上在折扣价格基础上再打5折
飞机的原价：2000元
年龄变量：&age
月份：&month
--使用两种方式实现（if else,  case when）
*/
declare
    v_age number(3);
    v_month number(2);
    v_price number(8,2) := 2000;
begin
    v_age := &age;
    v_month := &mon;
    
    -- 验证数据的有效性
    

    if v_age < 12 then
      v_price := 0;
    else
       -- 50岁以上
       if v_age > 50 then
         v_price := v_price*0.5;
       end if;
       -- 月份
       if v_month >= 4 and v_month <= 8 then
          v_price := v_price*0.88;
       else
          v_price := v_price*0.6;
       end if;
    end if;
    
    dbms_output.put_line('您的机票价格是:' || v_price || '元！');
    
end;


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

-- 1累加1~100之间能被3或5整除的数。输出结果。

-- 2处理一个字符串中间的空格，并且用一个'*'号替换。
--  如有字符串：'  a b   cd  ' 处理后：'  a*b*cd  '
--  请写一段代码实现。
declare
   v_leftsp varchar2(200);
   v_rightsp varchar2(200);
   v_str varchar2(200) := '  a  b   cd   ';
   v_result varchar2(200) := '';
   v_tmp varchar2(200);
begin
  
   --v_str := &a;
   -- 保存左边的空格
   v_leftsp := replace(v_str, ltrim(v_str), '');
   v_rightsp := replace(v_str, rtrim(v_str), '');
   
   -- 处理中间的空格
   -- 1:去掉两边空格，得到中间的字符串
   v_str := trim(v_str);
   
   while instr(v_str,' ') > 0 loop
       v_tmp := substr(v_str,1, instr(v_str,' ') - 1);
       v_result := v_result || v_tmp || '*';
       v_str := ltrim(substr(v_str,instr(v_str,' ')));
   end loop;
   
   v_result := v_leftsp || v_result || v_str || v_rightsp;
   
   dbms_output.put_line(v_result);
   
end;
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
--语法：for 临时变量 in (子查询) loop 代码块 end loop;
-- 在emp表中新增一列，”岗位“  薪水+奖金
--                            <1500 职员
--                            1500~3000 组长
--                            3000~4500 经理
--                            4500~ 股东
/*
alter table emp
add station nvarchar2(20);
*/
declare
   st nvarchar2(20);
begin
  
   for tmp in (select empno,sal+nvl(comm,0) sr from emp) loop
     
       st := (case  when tmp.sr <= 1500 then '职员' 
                    when tmp.sr <= 3000 then '组长'
                    when tmp.sr <= 4500 then '经理'
                    else '股东' end);
       update emp set station = st where empno = tmp.empno;
       
   end loop;
       commit;
end;

select * from emp;


-- 课堂作业1：
--在客户表中新增一个字段，保存会员的类型（级别） level
--(消费金额<100 青铜, 100-500之间 白银
--500-2000之间 黄金  2000-10000之间 白金
--10000-50000之间 钻石 50000以上  王者)
--根据客户的消费总金额来初始化会员的类型。（规则如上）


/*begin
  for i in (查询所有的客户信息) loop
     cash = 通过i.cusId查询当前客户消费的总金额
     result = (case when cash > 100000 then '王者' when cash > 100000 then '王者'....end);
     更新当前客户的cusType = result;
     update customer set cusType = result where cusid = i.cusid;
  end loop;
end;
*/

-- 分页
/*
-- 方法一
select *
  from (select rownum rn, s.*
          from ( ****查询的SQL语句**** ) s) t
 where t.rn between 3 and 4;
*/


