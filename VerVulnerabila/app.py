from flask import Flask, render_template, request, redirect, session, url_for, make_response
import psycopg2
import uuid

from datetime import datetime

app = Flask(__name__)
app.secret_key = "secretkey"  # hardcoded

# Configuratie vulnerabila pentru cookies
app.config['SESSION_COOKIE_HTTPONLY'] = False   # permite XSS
app.config['SESSION_COOKIE_SECURE'] = False     # merge și pe HTTP
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'    # permite CSRF

#expirare foarte lunga
app.permanent_session_lifetime = 60 * 60 * 24 * 30

# DB connection
conn = psycopg2.connect(database="flask_db", user="postgres",
                        password="pass", host="localhost", port="5432")
cur = conn.cursor()

def get_current_user():
    user_id = session.get('user_id')

    if not user_id:
        return None

    cur.execute("SELECT id, email, role, locked FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    return user

def can_access_ticket(user_id, ticket_id):
    cur.execute("""
        SELECT 1 FROM tickets
        WHERE id = %s AND owner_id = %s
    """, (ticket_id, user_id))

    return cur.fetchone() is not None

def is_manager(user):
    return user[2] == "MANAGER"

def log_action(user_id, action, resource, resource_id=None):
    ip = request.remote_addr

    cur.execute("""
        INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address)
        VALUES (%s, %s, %s, %s, NOW(), %s)
    """, (
        user_id,
        action,
        resource,
        str(resource_id) if resource_id else None,
        ip
    ))

    conn.commit()
    
########################################################################   
######### ---------------- REGISTER ---------------- ###################
########################################################################

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            return "User already exists"

        cur.execute("""
            INSERT INTO users (email, password_hash, role, created_at, locked)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            email,
            password,              #parola in text clar
            role,
            datetime.now(),
            False
        ))

        conn.commit()

        log_action(None, "REGISTER", "auth", email)


        return redirect('/login')

    return render_template('register.html')

#################################################################################################################
########################### ---------------- LOGIN ----------------  ##########################################
##############################################################################################################

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            log_action(None, "LOGIN_FAIL", "auth", email)
            return "User does not exist"  # user enumeration
        
        if user[5]:  # locked
            return "Account locked"

        if user[2] != password: 
            log_action(user[0], "LOGIN_FAIL", "auth", user[0])
            return "Wrong password"

        session.permanent = True

        session['user_id'] = user[0]
        session['email'] = user[1]

        log_action(user[0], "LOGIN", "auth", user[0])

        response = make_response(redirect('/'))

        response.set_cookie(
            'session_id',
            str(user[0]),
            httponly=False,
            secure=False,
            samesite=None,
            max_age=60 * 60 * 24 * 30
        )

        return response

    return render_template('login.html')

#########################################################################
############## ---------------- INDEX ----------------#########################
########################################################################

@app.route('/')
def index():

    user = get_current_user()

    if not user:
        return redirect('/login')

    user_id = user[0]
    role = user[2]

    log_action(user_id, "VIEW_TICKETS", "ticket", None)
    
    query = request.args.get('q', '')
    if role == "MANAGER":
        if query:
           cur.execute("""
                SELECT id, title, description, severity, status, created_at, updated_at
                FROM tickets
                WHERE title ILIKE %s
                ORDER BY created_at DESC
            """, (f"%{query}%",))
        else:
            cur.execute("""
                SELECT id, title, description, severity, status, created_at, updated_at
                FROM tickets
                ORDER BY created_at DESC
            """)
    else:
        # non manager
        if query:
            cur.execute("""
                SELECT id, title, description, severity, status, created_at, updated_at
                FROM tickets
                WHERE owner_id = %s AND title ILIKE %s
                ORDER BY created_at DESC
            """, (user_id, f"%{query}%"))
        else:
            cur.execute("""
                SELECT id, title, description, severity, status, created_at, updated_at
                FROM tickets
                WHERE owner_id = %s
                ORDER BY created_at DESC
            """, (user_id,))

    rows = cur.fetchall()

    tickets = [
        {
            "id": r[0],
            "title": r[1],
            "description": r[2],
            "severity": r[3],
            "status": r[4],
            "created_at": r[5],
            "updated_at": r[6]
        }
        for r in rows
    ]

    return render_template(
        'index.html',
        email=session['email'],
        tickets=tickets,
        query=query
    )
    
############################################ Create ########################################################################

@app.route('/tickets/create', methods=['POST'])
def create_ticket():

    user = get_current_user()
    if not user:
        return redirect('/login')
    
    cur.execute("""
        INSERT INTO tickets ( title, description, severity, status, owner_id, created_at, updated_at)
        VALUES ( %s, %s, %s, %s, %s, NOW(), NOW())
        RETURNING id
    """, (
        request.form['title'],
        request.form['description'],
        request.form['severity'],
        'OPEN',
        session['user_id']
    ))
    
    ticket_id = cur.fetchone()[0]
    
    conn.commit()
    
    log_action(session['user_id'], "CREATE_TICKET", "ticket", ticket_id)
    return redirect('/')

######################################## EDIT ########################################################################

@app.route('/tickets/edit/<ticket_id>', methods=['POST'])
def edit_ticket(ticket_id):
    
    user = get_current_user()
    if not user:
        return redirect('/login')
    if not can_access_ticket(user[0], ticket_id) and not is_manager(user):
        return "Unauthorized", 403

    cur.execute("""
        UPDATE tickets
        SET title = %s,
            description = %s,
            severity = %s,
            status = %s,
            updated_at = NOW()
        WHERE id = %s 
    """, (
        request.form['title'],
        request.form['description'],
        request.form['severity'],
        request.form['status'],
        ticket_id
    ))

    conn.commit()
    log_action(session['user_id'], "EDIT_TICKET", "ticket", ticket_id)
    return redirect('/')

#################################################### delete ########################################################################

@app.route('/tickets/delete/<ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):
    
    user = get_current_user()
    if not user:
        return redirect('/login')
    
    if not is_manager(user):
        return "Only manager can delete tickets", 403
    
    cur.execute("""
        DELETE FROM tickets
        WHERE id = %s
    """, (ticket_id, ))

    conn.commit()
    log_action(session['user_id'], "DELETE_TICKET", "ticket", ticket_id)
    return redirect('/')

#########################################################################################################
################### ---------------- LOGOUT ----------------###############################
#######################################################################################################

@app.route('/logout')
def logout():
    user_id = session.get('user_id')

    if user_id:
        log_action(user_id, "LOGOUT", "auth", user_id)
        
    session.clear()

    response = make_response(redirect('/login'))
    response.delete_cookie('session_id')

    return response

########################################################################################################
################# ---------------- FORGOT PASSWORD ----------------#############################
########################################################################################################
reset_tokens = {}  #in memory

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
   
    if request.method == 'POST':
        email = request.form['email']
        log_action(None, "FORGOT_PASSWORD", "auth", email)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            return "Email not found"

        token = str(uuid.uuid4())[:8]  #token slab
        reset_tokens[token] = email

        url = url_for('reset', token=token, _external=True)
        return f"Reset link: {url}"

    return render_template('forgot.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    
    if token not in reset_tokens:
        return "Invalid token"

    if request.method == 'POST':
        new_password = request.form['password']
        email = reset_tokens[token]
        log_action(None, "RESET_PASSWORD", "auth", email)
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (new_password, email)
        )
        conn.commit()

        return redirect('/login')

    return '''
        <form method="post">
            New password: <input type="password" name="password">
            <input type="submit">
        </form>
    '''


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)