from flask import *
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import pam
import subprocess
from src.iptables_parser import parse_iptables_output,get_chains
from src.restart import restart_iptables
app = Flask(__name__)
app.secret_key = 'iptables'  # Replace with a strong secret key
# Define available iptables tables
IPTABLES_TABLES = ['filter', 'nat', 'mangle', 'raw', 'security']

# Initialize PAM
p = pam.pam()

# Define the Login Form using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Please enter your username.")])
    password = PasswordField('Password', validators=[DataRequired(message="Please enter your password.")])
    submit = SubmitField('Login')

@app.route('/', methods=['GET', 'POST'])
def login():
    if('username' in session):
        return redirect("/dashboard")
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Authenticate using PAM
        if p.authenticate(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'],tables=IPTABLES_TABLES)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/iptables/<table_name>')
def iptables_table(table_name):
    rules_dict={}
    if 'username' not in session:
        flash('Please log in to access the iptables.', 'warning')
        return redirect(url_for('login'))
    
    if table_name not in IPTABLES_TABLES:
        flash('Invalid iptables table specified.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Retrieve iptables rules for the specified table
        result = subprocess.run(
            ['sudo', 'iptables','-t',table_name, '-L', '-n', '--line-numbers'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        raw_rules = result.stdout
        rules_dict = parse_iptables_output(raw_rules)
    except subprocess.CalledProcessError as e:
        flash(f'Error retrieving iptables table: {e.stderr}', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('iptables.html', table_name=table_name, rules=rules_dict)
@app.route("/rule/delete/<tablename>/<chainname>/<line>")
def delete_rule(tablename,chainname,line):
    if 'username' not in session:
        flash('Please log in to access the iptables.', 'warning')
        return redirect(url_for('login'))
    try:
        subprocess.run(
            ['sudo', 'iptables','-t',tablename, '-D', chainname,line],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        restart_iptables()
        flash('Please log in to access the dashboard.', 'warning')
    except Exception as e:
        flash(f"Error deleting :{e}",'danger')

    return redirect(f'/iptables/{tablename}')
@app.route("/ruleadd/<table>",methods=["GET","POST"])
def ruleadd(table):
    chains = get_chains(table)

    if request.method == 'POST':
        # Extract form data
        chain = request.form.get('chain')
        protocol = request.form.get('protocol')
        source_ip = request.form.get('source_ip')
        destination_ip = request.form.get('destination_ip')
        source_port = request.form.get('source_port')
        destination_port = request.form.get('destination_port')
        line_number = request.form.get('line_number')
        action = request.form.get('action')
        redirect_destination = request.form.get('redirect_destination') if action == 'DNAT' else None

        # Validation (basic checks, extend as needed)
        if not chain or not protocol or not source_ip or not destination_ip:
            flash('Please fill in all required fields.')
            return redirect(url_for('add_rule'))

        # Handle the form submission (e.g., add to iptables)
        # Here you would typically call a function to update iptables
        # For demonstration purposes, we simply print the data
        print(f'Adding rule: {chain}, {protocol}, {source_ip}, {destination_ip}, {source_port}, {destination_port}, {line_number}, {action}, {redirect_destination}')

        # Show a success message (optional)
        flash('Rule added successfully!')
        return redirect(url_for('add_rule'))

    return render_template("ruleadd.html",table=table,chains=chains)

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0")
