from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'keshav@ssn'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if the user is trying to log in
        if "lmail" in request.form:
            email = request.form.get('lmail')
            password = request.form['pass']
            # Hash the password before comparing it to the stored hash
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect('nbyula_terraformers.db')
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
            user = c.fetchone()
            conn.close()
            if user:
                # Store the username in the session
                session['user'] = user[0]
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid username or password'
                return render_template('index.html', error=error)
            
        # Check if the user is trying to sign up
        elif 'uname' in request.form:
            username = request.form['uname']
            email = request.form['mail']
            password = request.form['pwd']
            # Hash the password before storing it in the database
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect('nbyula_terraformers.db')
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
            user = c.fetchone()
            print(user)
            if user:
                error = 'Username already taken'
                conn.close()
                return render_template('index.html', error=error) 
            
            else:
                c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
                conn.commit()
                conn.close()
                return redirect(url_for('index'))
    else:
        return render_template('index.html')

@app.route('/schedule_appointment', methods=['GET', 'POST'])
def schedule_appointment():
    conn = sqlite3.connect('nbyula_terraformers.db')
    c = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']
        agenda = request.form['agenda']
        time = request.form['time']
        guest = request.form['guest']
        # Check if guest is available
        c.execute('SELECT off_hours FROM terraformers WHERE username=?', (guest,))
        off_hours = c.fetchone()[0]
        if time in off_hours:
            error = 'The guest is not available at this time.'
            return render_template('schedule_appointment.html', error=error)
        else:
            c.execute('INSERT INTO appointments (title, agenda, time, guest) VALUES (?, ?, ?, ?)',
                    (title, agenda, time, guest))
            conn.commit()
            return redirect(url_for('appointments'))
    else:
        terraformers = c.execute('SELECT username FROM users').fetchall()
        names = []
        for user in terraformers:
            names.append(user[0])
        return render_template('booking.html', terraformers=names)

@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'user' in session:
        conn = sqlite3.connect('nbyula_terraformers.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (session['user'],))
        user = c.fetchone()
        conn.close()
        return render_template('dashboard.html', user=user[0])
    else:
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
