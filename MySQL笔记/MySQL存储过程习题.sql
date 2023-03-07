-- 添加两条真实一点的用户信息，作为测试数据
-- 实现用户之间的转帐功能
--要求：
--1：接收用户输入的三个参数:转出用户名，转入用户名，转账的金额

--2：判断转出用户是否存在（根据输入的转出用户名与userName匹配查询），如果不存在，提示：转出账户不存在
--3：判断转入用户是否存在（根据输入的转入用户名与userName匹配查询），如果不存在，提示：转出账入不存在
--4：判断转出用户的余额是否>转账金额，如果不大于，提示：余额不足。
--5：正常转账
--6：记录日志(格式：logType固定为'ZZ',descriptions为：XXX在yyyy-mm-dd hh24:mi成功向XXX转入$$$金额。)

--补充：获取某表某列的数据类型   表名.列名%Type;

```sql
declare 
  v_ComeName varchar2(50);   -- 转出用户名
  v_enterName varchar2(50);  -- 转入用户名
  v_money number;           -- 转账金额
  v_count number := 0;        -- 记录转出用户是否存在
  v_ComeCount number := 0;    -- 记录转入用过是否存在
  myException exception;
begin
  v_ComeName := &v_ComeName;
  v_enterName := &v_enterName;
  v_money := &v_money;
  for temp in (select * from Account) loop
    if temp.userName = v_ComeName then        -- 判断转出用户是否存在
        v_count := v_count + 1;
    end if;
    if temp.userName = v_enterName then       -- 判断转入用户是否存在
        v_ComeCount := v_ComeCount + 1;
    end if;
  end loop;
  if v_count = 0 then                          -- 输出转出用户不存在
      dbms_output.put_line('转出用户不存在');   
  elsif v_ComeCount = 0 then                   -- 输除转入用户不存在
      dbms_output.put_line('转入用户不存在');    
  else                                         -- 以条件未满足表示转入转出用过都存在
      for temp in (select * from Account) loop
          if  temp.username = v_ComeName then          -- 判断余额是否大于转账金额     
             if temp.money > v_money then
                update account set account.money =  account.money - v_money where 								account.userName = v_ComeName;     -- 正常转账，修改转出用户金额     
                insert into "Log"(logId,logType,descriptions,createDate) 
                values((8),'ZZ',v_ComeName  || '向' || v_enterName ||'转入' || 										v_money || '金额成功', sysdate);
                dbms_output.put_line('转账成功！'); 
                for tep in (select * from Account) loop			-- 修改转入用户金额
                    if tep.username = v_enterName then
                       update account set account.money = account.money + v_money 
                       where account.username = v_enterName;
                    end if;
                end loop;
             elsif temp.money < v_money then
                dbms_output.put_line('转账失败,余额不足嘞您');
                raise myexception;
             end if;            
          end if; 
       end loop;
  end if;
  commit;
  exception
      when myexception then       -- 记录日志
      		rollback;
          insert into "Log"(logId,logType,descriptions,createDate) 
          values(5,'ZZSB',v_ComeName  || '向' || v_enterName ||'转入' || v_money || '金额失败', sysdate);
          dbms_output.put_line(sqlerrm);
end;
```





-- 作业1：根据工龄给员工涨工资和奖金(更新薪水列)
-- 涨工资的幅度算法：(当前年限-入职年限)*100
-- 涨奖金的幅度算法: 根据工资来增长：
--                   <= 1000 涨100  
--                   1000 到 1500之间 涨200  
--                   1500 以上 涨300  
-- 请编写一段程序，完成以上业务需求（代码块中是可以写DML语句的）。

```sql
declare 
    v_age number(4);        -- 入职年限
    v_SalMoney number(10,2);      -- 涨-工资数
    v_CommBouns number(10,2);     -- 涨-奖金数
begin
    v_SalMoney := 0;
    for temp in (select empno,hiredate,sal,comm from emp) loop
        v_age := to_char(to_date(sysdate),'yyyy') - to_char(to_date(temp.hiredate),'yyyy');
        v_SalMoney := v_age * 100;      -- 求出涨工资数
        if  temp.comm <= 1000 then
            v_CommBouns := 100;
        elsif temp.comm > 1000 and temp.comm <= 1500 then
            v_CommBouns := 200;
        elsif temp.comm > 1500 then
            v_CommBouns := 300;
        end if;
        update emp set emp.sal = nvl(emp.sal,0) + v_SalMoney 
        where emp.empno = temp.empno;     -- 更新工资
        dbms_output.put_line(temp.empno ||'涨工资' || v_SalMoney ||' 元');
        update emp set emp.comm = nvl(emp.comm,0) + v_CommBouns 
        where emp.empno = temp.empno;     -- 更新奖金
        dbms_output.put_line(temp.empno ||'涨奖金' || v_CommBouns ||' 元');
        dbms_output.put_line('-----------------');
    end loop;
    -- commit;
end;
```





--作业2：定义一个函数：处理一个字符串,超过指定个数的字符后面以...代替,没有超过，不处理

```sql
create or replace function DisposeStr (v_str varchar2,v_number number)
return varchar2
as
    v_temp varchar2(50);         -- 存储的处理后的字符串
    v_length number(10) := 0;
    DisposeStrException exception;
begin
    v_length := length(v_str);
    if v_length <= v_number then
        return v_str;
    elsif v_length > v_number then
        v_temp := substr(v_str,1,v_number);
        v_temp := v_temp || '...';
        return v_temp;
    else
        raise DisposeStrException;
    end if;
    exception
        when  DisposeStrException then
            dbms_output.put_line('传入数据错误');
            return null;
end DisposeStr;
```





--作业3：定义一个函数：提取字符串中的所有数字,返回所有数字相连的数字字符串。



```sql
create or replace function ExtractStr (v_str varchar2)
return varchar2
is
    v_tempStr varchar2(200) := '';			-- 返回的字符串
    v_temp varchar(200) := '';					-- 中间操作
    v_length number := 0;								-- 传入字符串长度
    v_char varchar(10) := '';						-- 
begin
    v_length := length(v_str);
    for i in 1..v_length loop						-- 每次循环获取字符串中一个字符
         for j in 1..9 loop							-- 将数字转化为字符与字符串中的字符比较
             v_temp := substr(v_str,i,1);
             v_char := to_char(j);
             if v_temp = v_char then
                v_tempStr := v_tempStr || v_temp;		-- 拼接数字字符串
             end if;
         end loop;
    end loop;
    return v_tempStr;
end ExtractStr;


```







