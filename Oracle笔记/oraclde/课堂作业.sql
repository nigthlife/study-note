select * from 
(select row_number() over(partition by sex order by ))


select * from 
       (select table_alias)
       
       
       select * from 
        (select rownum as rowno, t.* from emp t
         where hiredate between to_date('20060501','yyyymmdd')
         and to_date ('20060731','yyyymmdd')
         and rownum <= 20) table_alias 
         where  table_alias.rowno >= 10 );
