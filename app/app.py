import os
import secrets
from functools import wraps
from datetime import timedelta
import click
import pymysql
from pymysql.cursors import DictCursor
from flask import Flask, g, session, request, render_template, redirect, url_for, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from domain import normalize_target, dump, snapshot, parse_json, decision

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ['SECRET_KEY'], SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=False,
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=2), MAX_CONTENT_LENGTH=128*1024)


def db():
    if 'db' not in g:
        g.db = pymysql.connect(host=os.environ.get('DB_HOST','db'), port=int(os.environ.get('DB_PORT','3306')),
            user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'], database=os.environ['DB_NAME'],
            charset='utf8mb4', cursorclass=DictCursor, autocommit=False, connect_timeout=5, read_timeout=15, write_timeout=15)
    return g.db


def rows(sql, args=()):
    with db().cursor() as c:
        c.execute(sql, args)
        return c.fetchall()


def one(sql, args=()):
    result = rows(sql,args)
    return result[0] if result else None


def write(sql, args=()):
    with db().cursor() as c:
        c.execute(sql,args)
        return c.lastrowid


def lock_writes():
    # Serialize writes for the single simulated enforcement point, including role changes.
    if not one("SELECT GET_LOCK('netaccess_lab_write_v1', 10) AS acquired")['acquired']:
        abort(503, 'Hệ thống đang bận. Thử lại sau.')


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop('db', None)
    if conn:
        try:
            conn.rollback()
        except pymysql.MySQLError:
            pass
        finally:
            conn.close()  # also releases connection-level named lock


USER_SELECT = 'SELECT u.user_id,u.username,u.full_name,u.role_id,u.account_status,r.role_code FROM users u JOIN roles r USING(role_id)'
ENTRY_SELECT = 'SELECT entry_id,list_type,target_type,target_value,description,entry_status,version_no,created_at,updated_at,deactivated_at FROM list_entries'
REQ_SELECT = '''SELECT c.*,u.username AS requester_name,v.username AS reviewer_name
 FROM change_requests c JOIN users u ON u.user_id=c.requested_by LEFT JOIN users v ON v.user_id=c.reviewed_by'''


def audit(action, entity, entity_id=None, req_id=None, outcome='SUCCESS', old=None, new=None, detail=None, actor=None):
    actor = actor if actor is not None else getattr(g,'user',None)
    write('''INSERT INTO audit_logs(actor_user_id,actor_role_code,request_id,entity_type,entity_id,action_code,outcome,old_data,new_data,detail)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
          (actor['user_id'] if actor else None,actor['role_code'] if actor else None,req_id,entity,entity_id,action,outcome,dump(old),dump(new),detail))


@app.before_request
def prepare():
    if request.endpoint in ('health','static'):
        return
    if request.method == 'POST':
        token=session.get('csrf','')
        if not token or not secrets.compare_digest(token,request.form.get('csrf','')):
            abort(400,'Phiên biểu mẫu không hợp lệ. Tải lại trang.')
        lock_writes()
    g.user = None
    if session.get('uid'):
        g.user=one(USER_SELECT+' WHERE u.user_id=%s',(session['uid'],))
        if not g.user or g.user['account_status']!='ACTIVE':
            session.clear(); g.user=None
    session.setdefault('csrf',secrets.token_hex(32))


def require(*roles):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            if not g.user: return redirect(url_for('login'))
            if roles and g.user['role_code'] not in roles:
                if request.method=='POST':
                    audit('ACCESS_DENIED','AUTH',outcome='DENIED',detail=request.endpoint); db().commit()
                abort(403)
            return fn(*a,**kw)
        return wrapped
    return decorate


def page(title, view, **kwargs):
    return render_template('main.html',title=title,view=view,**kwargs)


def finish(message, endpoint, category='success', **kw):
    db().commit(); flash(message,category); return redirect(url_for(endpoint,**kw))


def textfield(name, maxlen=4000, required=True):
    val=request.form.get(name,'').strip()
    if (required and not val) or len(val)>maxlen: raise ValueError(f'Trường {name} thiếu hoặc quá dài.')
    return val


def choice(name, options):
    value=request.form.get(name,'')
    if value not in options: raise ValueError(f'Giá trị {name} không hợp lệ.')
    return value


def get_request(rid, lock=False):
    # Lock the request row itself before reading joined display data.
    if lock: one('SELECT request_id FROM change_requests WHERE request_id=%s FOR UPDATE',(rid,))
    r=one(REQ_SELECT+' WHERE c.request_id=%s',(rid,))
    if not r: abort(404)
    if g.user['role_code']=='REQUESTER' and r['requested_by']!=g.user['user_id']: abort(403)
    return r


def entry(kind,val,list_type):
    return one(ENTRY_SELECT+" WHERE target_type=%s AND target_value=%s AND list_type=%s AND entry_status='ACTIVE'",(kind,val,list_type))


def opposite(kind,val,list_type):
    return entry(kind,val,'BLACKLIST' if list_type=='WHITELIST' else 'WHITELIST')


def current_matches(r):
    current=entry(r['target_type'],r['target_value'],r['list_type'])
    conflict=opposite(r['target_type'],r['target_value'],r['list_type'])
    if r['change_action']=='ADD': valid=current is None
    else: valid=current is not None and current['entry_id']==r['target_entry_id'] and current['version_no']==r['target_version'] and snapshot(current)==parse_json(r['before_snapshot'])
    return valid and snapshot(conflict)==parse_json(r['conflict_snapshot']),current


@app.get('/health')
def health():
    try:
        count=one('SELECT COUNT(*) AS n FROM roles')['n']
        return jsonify(status='ok' if count==3 else 'not_ready', database='netaccess_manager', mode='SIMULATED'), 200 if count==3 else 503
    except pymysql.MySQLError:
        return jsonify(status='database_unavailable'),503


@app.route('/login',methods=['GET','POST'])
def login():
    if g.user: return redirect(url_for('home'))
    if request.method=='POST':
        name=request.form.get('username','').strip()[:64]; password=request.form.get('password','')
        user=one(USER_SELECT+' WHERE u.username=%s',(name,))
        hashed=one('SELECT password_hash FROM users WHERE user_id=%s',(user['user_id'],)) if user else None
        valid=bool(user and len(password)<=256 and check_password_hash(hashed['password_hash'],password) and user['account_status']=='ACTIVE')
        if valid:
            session.clear(); session['uid']=user['user_id']; session.permanent=True; session['csrf']=secrets.token_hex(32)
            audit('LOGIN','AUTH',actor=user); return finish('Đăng nhập thành công.','home')
        audit('LOGIN_FAILED','AUTH',outcome='FAILED',actor=user,detail='Thông tin xác thực không hợp lệ hoặc tài khoản bị khóa.'); db().commit()
        flash('Tên đăng nhập, mật khẩu hoặc trạng thái tài khoản không hợp lệ.','error')
    return page('Đăng nhập','login')


@app.post('/logout')
@require()
def logout():
    audit('LOGOUT','AUTH'); db().commit(); session.clear(); return redirect(url_for('login'))


@app.get('/')
@require()
def home():
    scope=' WHERE requested_by=%s' if g.user['role_code']=='REQUESTER' else ''
    args=(g.user['user_id'],) if scope else ()
    counts=rows('SELECT request_status,COUNT(*) AS n FROM change_requests'+scope+' GROUP BY request_status',args)
    lists=rows("SELECT list_type,COUNT(*) AS n FROM list_entries WHERE entry_status='ACTIVE' GROUP BY list_type")
    recent=rows(REQ_SELECT+(' WHERE c.requested_by=%s' if scope else '')+' ORDER BY c.created_at DESC LIMIT 8',args)
    return page('Tổng quan','home',counts=counts,lists=lists,recent=recent)


@app.get('/entries')
@require()
def entries():
    q=request.args.get('q','')[:253]; lt=request.args.get('list_type',''); status=request.args.get('status','ACTIVE')
    conditions=['target_value LIKE %s']; args=['%'+q+'%']
    if lt in ('WHITELIST','BLACKLIST'): conditions.append('list_type=%s'); args.append(lt)
    if status in ('ACTIVE','INACTIVE'): conditions.append('entry_status=%s'); args.append(status)
    result=rows(ENTRY_SELECT+' WHERE '+' AND '.join(conditions)+' ORDER BY entry_id DESC LIMIT 200',args)
    return page('Whitelist / Blacklist','entries',items=result,q=q,lt=lt,status=status)


@app.get('/requests')
@require()
def requests_list():
    q=request.args.get('q','')[:253]; status=request.args.get('status',''); conditions=['(c.request_code LIKE %s OR c.target_value LIKE %s)']; args=['%'+q+'%']*2
    if g.user['role_code']=='REQUESTER': conditions.append('c.requested_by=%s'); args.append(g.user['user_id'])
    if status in ('PENDING','APPROVED','REJECTED','APPLYING','APPLIED','APPLY_FAILED','INVALIDATED'): conditions.append('c.request_status=%s'); args.append(status)
    result=rows(REQ_SELECT+' WHERE '+' AND '.join(conditions)+' ORDER BY c.created_at DESC LIMIT 200',args)
    return page('Đề xuất và lịch sử','requests',items=result,q=q,status=status)


@app.route('/requests/new',methods=['GET','POST'])
@require('REQUESTER')
def new_request():
    draft = dict(list_type='WHITELIST', change_action='ADD', target_type='DOMAIN',
                 target_value='', description='', reason='', conflict_ack='')
    errors = {}
    if request.method == 'POST':
        draft = {name: request.form.get(name, '') for name in draft}
        kind, lt, action = draft['target_type'], draft['list_type'], draft['change_action']
        for name, options, message in (
            ('list_type', ('WHITELIST', 'BLACKLIST'), 'Hãy chọn Whitelist hoặc Blacklist.'),
            ('change_action', ('ADD', 'UPDATE', 'REMOVE'), 'Hãy chọn hành động cần thực hiện.'),
            ('target_type', ('IPV4', 'DOMAIN'), 'Hãy chọn tên miền hoặc địa chỉ IPv4.'),
        ):
            if draft[name] not in options:
                errors[name] = message

        val = draft['target_value'].strip()
        if not val:
            errors['target_value'] = 'Hãy nhập giá trị đích.'
        elif len(val) > 253:
            errors['target_value'] = 'Giá trị đích chỉ được dài tối đa 253 ký tự.'
        elif 'target_type' not in errors:
            try:
                val = normalize_target(kind, val)
            except ValueError:
                errors['target_value'] = (
                    'Hãy nhập một địa chỉ IPv4 hợp lệ, ví dụ 192.0.2.10.' if kind == 'IPV4'
                    else 'Hãy nhập tên miền như docs.example.test, bỏ https://, đường dẫn và ký tự đại diện.'
                )

        reason = draft['reason'].strip()
        if not reason:
            errors['reason'] = 'Hãy nhập lý do đề xuất.'
        elif len(reason) > 4000:
            errors['reason'] = 'Lý do chỉ được dài tối đa 4.000 ký tự.'

        desc = None
        if action in ('ADD', 'UPDATE'):
            desc = draft['description'].strip()
            if not desc:
                errors['description'] = 'Hãy nhập mô tả quy tắc.'
            elif len(desc) > 4000:
                errors['description'] = 'Mô tả chỉ được dài tối đa 4.000 ký tự.'

        if not errors:
            current = entry(kind, val, lt)
            conflict = opposite(kind, val, lt)
            if action == 'ADD' and current:
                errors['target_value'] = 'Đích này đã có quy tắc đang hiệu lực trong danh sách bạn chọn. Hãy kiểm tra lại đích hoặc hành động.'
            elif action != 'ADD' and not current:
                errors['target_value'] = 'Không tìm thấy quy tắc đang hiệu lực để sửa hoặc gỡ. Hãy kiểm tra lại danh sách và giá trị đích.'
            elif one("SELECT request_id FROM change_requests WHERE target_type=%s AND target_value=%s AND open_slot=1", (kind, val)):
                errors['target_value'] = 'Đích này đang có đề xuất xử lý. Hãy đợi đề xuất đó kết thúc rồi gửi lại.'
            elif conflict and draft['conflict_ack'] != 'yes':
                errors['conflict_ack'] = 'Đích này có quy tắc ở danh sách đối lập. Blacklist được ưu tiên chặn. Hãy đánh dấu xác nhận nếu vẫn muốn gửi.'
            else:
                rid = write('''INSERT INTO change_requests(request_code,requested_by,list_type,target_type,target_value,change_action,target_entry_id,target_version,before_snapshot,conflict_snapshot,proposed_description,reason)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    ('REQ-' + secrets.token_hex(8).upper(), g.user['user_id'], lt, kind, val, action,
                     current['entry_id'] if current else None, current['version_no'] if current else None,
                     dump(current), dump(conflict), desc, reason))
                audit('REQUEST_CREATED', 'REQUEST', rid, rid,
                      new={'status': 'PENDING', 'target': val, 'action': action, 'list_type': lt, 'description': desc, 'reason': reason})
                return finish('Đã gửi đề xuất. Danh sách chưa thay đổi.', 'request_detail', rid=rid)

    return page('Tạo đề xuất thay đổi', 'new', draft=draft, errors=errors), 400 if errors else 200


@app.get('/requests/<int:rid>')
@require()
def request_detail(rid):
    r=get_request(rid)
    deployments=rows('''SELECT d.*,u.username AS actor_name FROM deployment_logs d JOIN users u ON u.user_id=d.applied_by WHERE request_id=%s ORDER BY attempt_no''',(rid,))
    history=rows('SELECT * FROM audit_logs WHERE request_id=%s ORDER BY audit_id',(rid,))
    return page('Chi tiết '+r['request_code'],'detail',r=r,deployments=deployments,history=history)


@app.post('/requests/<int:rid>/review')
@require('APPROVER')
def review(rid):
    r=get_request(rid,True); result=choice('decision',('APPROVED','REJECTED')); note=textfield('note',required=result=='REJECTED' or (result=='APPROVED' and r['conflict_snapshot'] is not None))
    if r['request_status']!='PENDING' or r['requested_by']==g.user['user_id']: raise ValueError('Không được xử lý yêu cầu này.')
    if result=='APPROVED' and not current_matches(r)[0]: raise ValueError('Dữ liệu đã thay đổi; từ chối yêu cầu và đề nghị lập lại.')
    write('UPDATE change_requests SET reviewed_by=%s,reviewed_at=NOW(6),review_decision=%s,review_note=%s,request_status=%s WHERE request_id=%s',(g.user['user_id'],result,note or None,result,rid))
    audit('REQUEST_'+result,'REQUEST',rid,rid,old={'status':'PENDING'},new={'status':result},detail=note)
    return finish('Đã ghi quyết định.','request_detail',rid=rid)


@app.post('/requests/<int:rid>/apply')
@require('ADMIN')
def apply(rid):
    r=get_request(rid,True); uid=g.user['user_id']; status=r['request_status']
    if status not in ('APPROVED','APPLY_FAILED') or uid in (r['requested_by'],r['reviewed_by']): raise ValueError('Chưa được duyệt hoặc vi phạm phân tách nhiệm vụ.')
    if one('SELECT deployment_id FROM deployment_logs WHERE request_id=%s AND (blocking_slot=1 OR success_slot=1)',(rid,)): raise ValueError('Đang thực hiện, chờ đối soát hoặc đã thành công.')
    valid,current=current_matches(r)
    if not valid:
        msg='Quy tắc hoặc xung đột đã thay đổi kể từ khi gửi đề xuất.'
        write("UPDATE change_requests SET request_status='INVALIDATED',invalid_reason=%s WHERE request_id=%s",(msg,rid)); audit('REQUEST_INVALIDATED','REQUEST',rid,rid,old={'status':status},new={'status':'INVALIDATED'},detail=msg)
        return finish(msg,'request_detail',category='error',rid=rid)
    attempt=one('SELECT COALESCE(MAX(attempt_no),0)+1 AS n FROM deployment_logs WHERE request_id=%s',(rid,))['n']
    write("UPDATE change_requests SET request_status='APPLYING' WHERE request_id=%s",(rid,))
    did=write("INSERT INTO deployment_logs(request_id,attempt_no,applied_by,execution_mode,before_snapshot) VALUES(%s,%s,%s,'SIMULATED',%s)",(rid,attempt,uid,dump(current)))
    audit('DEPLOYMENT_STARTED','DEPLOYMENT',did,rid,old={'status':status},new={'status':'APPLYING','attempt':attempt})
    # Simulation uses one atomic DB transaction. No external proxy/firewall I/O.
    if request.form.get('simulate_failure')=='yes':
        msg='Lỗi mô phỏng có chủ đích; xác nhận chưa thay đổi danh sách.'
        write("UPDATE deployment_logs SET result='FAILED',finished_at=NOW(6),result_detail=%s,after_snapshot=%s WHERE deployment_id=%s",(msg,dump(current),did))
        write("UPDATE change_requests SET request_status='APPLY_FAILED' WHERE request_id=%s",(rid,))
        audit('DEPLOYMENT_FAILED','DEPLOYMENT',did,rid,outcome='FAILED',old=current,new=current,detail=msg)
        return finish(msg,'request_detail',category='error',rid=rid)
    action=r['change_action']
    if action=='ADD':
        eid=write('INSERT INTO list_entries(list_type,target_type,target_value,description) VALUES(%s,%s,%s,%s)',(r['list_type'],r['target_type'],r['target_value'],r['proposed_description']))
    else:
        eid=current['entry_id']
        if action=='UPDATE': write('UPDATE list_entries SET description=%s,version_no=version_no+1 WHERE entry_id=%s',(r['proposed_description'],eid))
        else: write("UPDATE list_entries SET entry_status='INACTIVE',deactivated_at=NOW(6),version_no=version_no+1 WHERE entry_id=%s",(eid,))
    after=one(ENTRY_SELECT+' WHERE entry_id=%s',(eid,))
    expected_version=1 if action=='ADD' else current['version_no']+1
    if not after or after['entry_status']!=('INACTIVE' if action=='REMOVE' else 'ACTIVE') or after['version_no']!=expected_version or (action!='REMOVE' and after['description']!=r['proposed_description']): raise ValueError('Không xác minh được kết quả mô phỏng; giao dịch đã hủy.')
    msg='Xác minh thành công trong cơ sở dữ liệu Lab; không thay đổi mạng thật.'
    write("UPDATE deployment_logs SET result='SUCCESS',finished_at=NOW(6),after_snapshot=%s,result_detail=%s WHERE deployment_id=%s",(dump(after),msg,did))
    write("UPDATE change_requests SET request_status='APPLIED',applied_entry_id=%s WHERE request_id=%s",(eid,rid))
    audit('ENTRY_'+action,'ENTRY',eid,rid,old=current,new=after)
    audit('DEPLOYMENT_SUCCESS','DEPLOYMENT',did,rid,new={'status':'APPLIED','entry_id':eid},detail=msg)
    return finish(msg,'request_detail',rid=rid)


@app.route('/policy',methods=['GET','POST'])
@require('ADMIN')
def policy():
    result=None
    if request.method=='POST':
        kind=choice('target_type',('IPV4','DOMAIN')); val=normalize_target(kind,textfield('target_value',253)); extra=textfield('destination_ip',required=False)
        conditions=['(target_type=%s AND target_value=%s)']; args=[kind,val]
        if extra:
            if kind!='DOMAIN': raise ValueError('IP bổ sung chỉ dùng khi kiểm tra tên miền.')
            conditions.append("(target_type='IPV4' AND target_value=%s)"); args.append(normalize_target('IPV4',extra))
        matched=rows(ENTRY_SELECT+" WHERE entry_status='ACTIVE' AND ("+' OR '.join(conditions)+')',args)
        verdict,why=decision(matched); result={'verdict':verdict,'why':why,'matched':matched,'target':val}
        audit('POLICY_CHECK','POLICY_CHECK',new={'target':val,'ip':extra or None,'verdict':verdict},detail=why); db().commit()
    return page('Kiểm chứng Allow / Block','policy',result=result)


@app.get('/audit')
@require('ADMIN')
def audit_view():
    q=request.args.get('q','')[:100]
    items=rows('''SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.user_id=a.actor_user_id WHERE a.action_code LIKE %s OR u.username LIKE %s ORDER BY a.audit_id DESC LIMIT 200''',('%'+q+'%','%'+q+'%'))
    return page('Nhật ký kiểm toán','audit',items=items,q=q)


@app.route('/users',methods=['GET','POST'])
@require('ADMIN')
def users():
    if request.method=='POST':
        name=textfield('username',64); full=textfield('full_name',150); role=choice('role_id',('1','2','3')); password=request.form.get('password','')
        if not 12<=len(password)<=128: raise ValueError('Mật khẩu phải có 12–128 ký tự.')
        if one('SELECT user_id FROM users WHERE username=%s',(name,)): raise ValueError('Tên đăng nhập đã tồn tại.')
        uid=write('INSERT INTO users(username,full_name,role_id,password_hash) VALUES(%s,%s,%s,%s)',(name,full,role,generate_password_hash(password)))
        audit('ACCOUNT_CREATED','USER',uid,new={'username':name,'full_name':full,'role_id':role}); return finish('Đã tạo tài khoản.','users')
    return page('Tài khoản và phân quyền','users',items=rows(USER_SELECT+' ORDER BY user_id'))


@app.post('/users/<int:uid>/edit')
@require('ADMIN')
def user_edit(uid):
    old=one(USER_SELECT+' WHERE u.user_id=%s',(uid,))
    if not old: abort(404)
    role=int(choice('role_id',('1','2','3'))); status=choice('account_status',('ACTIVE','LOCKED')); full=textfield('full_name',150)
    if uid==g.user['user_id'] and (role!=old['role_id'] or status!='ACTIVE'): raise ValueError('Không được tự đổi vai trò hoặc khóa tài khoản của mình.')
    write('UPDATE users SET full_name=%s,role_id=%s,account_status=%s WHERE user_id=%s',(full,role,status,uid))
    new=one(USER_SELECT+' WHERE u.user_id=%s',(uid,)); audit('ACCOUNT_UPDATED','USER',uid,old=old,new=new); return finish('Đã cập nhật tài khoản.','users')


@app.errorhandler(ValueError)
def business_error(exc):
    if 'db' in g: db().rollback()
    return page('Không thể thực hiện','error',message=str(exc)),400


@app.errorhandler(pymysql.MySQLError)
def database_error(exc):
    if 'db' in g:
        try: db().rollback()
        except pymysql.MySQLError: pass
    app.logger.error('Database operation failed: %s',type(exc).__name__)
    return page('Lỗi cơ sở dữ liệu','error',message='Không xác nhận được thao tác. Hãy tải lại lịch sử để kiểm tra kết quả trước khi thử lại.'),503


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(503)
def http_error(exc):
    return page('Thông báo','error',message=exc.description),exc.code


@app.cli.command('seed-demo')
def seed_demo():
    """Create three distinct Lab accounts, prompting for passwords."""
    lock_writes()
    if one('SELECT COUNT(*) AS n FROM users')['n']:
        raise click.ClickException('Database đã có tài khoản. Không ghi đè.')
    for username,role,full in [('requester',1,'Nhân viên IT'),('approver',2,'Cán bộ ATTT'),('admin',3,'Quản trị viên mạng')]:
        password=click.prompt(f'Mật khẩu {username} (12–128 ký tự)',hide_input=True,confirmation_prompt=True)
        if not 12<=len(password)<=128: raise click.ClickException('Mật khẩu phải dài 12–128 ký tự. Không có tài khoản nào được lưu.')
        uid=write('INSERT INTO users(username,role_id,full_name,password_hash) VALUES(%s,%s,%s,%s)',(username,role,full,generate_password_hash(password)))
        audit('BOOTSTRAP_ACCOUNT','USER',uid,new={'username':username,'role_id':role},detail='Khởi tạo Lab qua CLI')
    db().commit(); click.echo('Đã tạo requester, approver, admin.')


@app.cli.command('verify-db')
def verify_db():
    """Read-only check of schema shape and roles."""
    tables = {r['TABLE_NAME'] for r in rows("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE'")}
    expected = {'roles','users','list_entries','change_requests','deployment_logs','audit_logs'}
    fks = one("SELECT COUNT(*) AS n FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL")['n']
    role_codes = {r['role_code'] for r in rows('SELECT role_code FROM roles')}
    click.echo(f'Tables ({len(tables)}): {", ".join(sorted(tables))}')
    click.echo(f'Foreign keys: {fks}; roles: {", ".join(sorted(role_codes))}')
    if tables != expected or fks != 10 or role_codes != {'REQUESTER','APPROVER','ADMIN'}:
        raise click.ClickException('Schema does not match the approved Lab design.')
    click.echo('Database schema OK.')
