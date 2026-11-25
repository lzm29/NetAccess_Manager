-- The official image creates netaccess_app before running initialization SQL.
-- Revoke broad schema grant, then grant only operations required by the Lab.
REVOKE ALL PRIVILEGES ON netaccess_manager.* FROM 'netaccess_app'@'%';
GRANT SELECT ON netaccess_manager.roles TO 'netaccess_app'@'%';
GRANT SELECT, INSERT, UPDATE ON netaccess_manager.users TO 'netaccess_app'@'%';
GRANT SELECT, INSERT, UPDATE ON netaccess_manager.list_entries TO 'netaccess_app'@'%';
GRANT SELECT, INSERT, UPDATE ON netaccess_manager.change_requests TO 'netaccess_app'@'%';
GRANT SELECT, INSERT, UPDATE ON netaccess_manager.deployment_logs TO 'netaccess_app'@'%';
GRANT SELECT, INSERT ON netaccess_manager.audit_logs TO 'netaccess_app'@'%';
