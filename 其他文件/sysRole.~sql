-- 创建序列
drop Sequence S_sys_role;
create Sequence S_sys_role;

drop table sys_role;
-- 创建角色表
create table sys_role(
    roleId number primary key,                -- 角色id
    roleName nvarchar2(30) not null unique,   -- 角色名称
    roleNo nvarchar2(30) not null            -- 角色编号
);

insert into sys_role(roleID,roleName,roleNo) values(S_sys_role.nextVal,'管理员','R001');
insert into sys_role(roleID,roleName,roleNo) values(S_sys_role.nextVal,'花老板','R002');
commit;

select * from sys_role;
