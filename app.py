from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = 'canteen_management_secret_key_2024'

DATABASE = 'canteen.db'


# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'staff')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Products table with category
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Sales table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER,
            student_name TEXT,
            payment_method TEXT NOT NULL CHECK(payment_method IN ('Cash', 'GCash')),
            total_amount REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (staff_id) REFERENCES users(id)
        )
    ''')

    # Sale items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            line_total REAL NOT NULL,
            FOREIGN KEY (sale_id) REFERENCES sales(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize database on startup
if not os.path.exists(DATABASE):
    init_db()
    # Create default admin account
    conn = get_db()
    cursor = conn.cursor()
    admin_hash = generate_password_hash('admin123')
    cursor.execute(
        'INSERT OR IGNORE INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
        ('admin', 'admin@canteen.com', admin_hash, 'admin')
    )
    conn.commit()
    conn.close()


# Helper function to generate GCash QR Code
def generate_qr_code(amount, reference):
    # Format: GCash payment string
    qr_data = f"GCASH|{reference}|{amount:.2f}"

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return img_str


# Routes
@app.route('/')
def home():
    return render_template('home.html')


# Student ordering page (no login required)
@app.route('/order')
def student_order():
    conn = get_db()
    cursor = conn.cursor()

    # Get all available products grouped by category
    products = cursor.execute('''
        SELECT * FROM products 
        WHERE stock > 0 
        ORDER BY category, name
    ''').fetchall()

    # Get unique categories
    categories = cursor.execute('''
        SELECT DISTINCT category FROM products 
        WHERE stock > 0 
        ORDER BY category
    ''').fetchall()

    conn.close()

    return render_template('student_order.html', products=products, categories=categories)


# Process student order
@app.route('/process_student_order', methods=['POST'])
def process_student_order():
    student_name = request.form.get('student_name', 'Walk-in Customer')
    payment_method = request.form['payment_method']

    conn = get_db()
    cursor = conn.cursor()

    # Get all products
    products = cursor.execute('SELECT * FROM products').fetchall()

    selected_items = []
    total_amount = 0

    for product in products:
        qty_key = f'qty_{product["id"]}'
        quantity = int(request.form.get(qty_key, 0))

        if quantity > 0:
            if quantity > product['stock']:
                flash(f'Not enough stock for {product["name"]}!', 'error')
                conn.close()
                return redirect(url_for('student_order'))

            line_total = product['price'] * quantity
            selected_items.append({
                'id': product['id'],
                'name': product['name'],
                'price': product['price'],
                'quantity': quantity,
                'line_total': line_total
            })
            total_amount += line_total

    if not selected_items:
        flash('Please select at least one item!', 'error')
        conn.close()
        return redirect(url_for('student_order'))

    # Create sale record (no staff_id for student orders)
    cursor.execute(
        'INSERT INTO sales (staff_id, student_name, payment_method, total_amount) VALUES (?, ?, ?, ?)',
        (None, student_name, payment_method, total_amount)
    )
    sale_id = cursor.lastrowid

    # Add sale items and update stock
    for item in selected_items:
        cursor.execute(
            'INSERT INTO sale_items (sale_id, product_id, quantity, unit_price, line_total) VALUES (?, ?, ?, ?, ?)',
            (sale_id, item['id'], item['quantity'], item['price'], item['line_total'])
        )
        cursor.execute(
            'UPDATE products SET stock = stock - ? WHERE id = ?',
            (item['quantity'], item['id'])
        )

    conn.commit()
    conn.close()

    # Redirect to payment page if GCash
    if payment_method == 'GCash':
        return redirect(url_for('gcash_payment', sale_id=sale_id))
    else:
        return redirect(url_for('student_receipt', sale_id=sale_id))


# GCash payment page
@app.route('/gcash_payment/<int:sale_id>')
def gcash_payment(sale_id):
    conn = get_db()
    cursor = conn.cursor()

    sale = cursor.execute('SELECT * FROM sales WHERE id = ?', (sale_id,)).fetchone()
    conn.close()

    if not sale:
        flash('Order not found!', 'error')
        return redirect(url_for('student_order'))

    # Generate QR code
    qr_code = generate_qr_code(sale['total_amount'], f"ORDER-{sale_id}")

    return render_template('gcash_payment.html', sale=sale, qr_code=qr_code)


# Student receipt
@app.route('/student_receipt/<int:sale_id>')
def student_receipt(sale_id):
    conn = get_db()
    cursor = conn.cursor()

    sale = cursor.execute('SELECT * FROM sales WHERE id = ?', (sale_id,)).fetchone()
    items = cursor.execute('''
        SELECT si.*, p.name as product_name
        FROM sale_items si
        JOIN products p ON si.product_id = p.id
        WHERE si.sale_id = ?
    ''', (sale_id,)).fetchall()

    conn.close()

    return render_template('student_receipt.html', sale=sale, items=items)


# Staff/Admin Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        user = cursor.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1',
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'admin':
                flash('Welcome back, Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Welcome, ' + user['username'] + '!', 'success')
                return redirect(url_for('staff_dashboard'))
        else:
            flash('Invalid credentials!', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'staff')

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, role)
            )
            conn.commit()
            conn.close()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Please login as admin first!', 'error')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    products = cursor.execute('SELECT * FROM products ORDER BY category, name').fetchall()
    staff_members = cursor.execute('SELECT * FROM users WHERE role = "staff" ORDER BY username').fetchall()

    # Get statistics
    total_sales = cursor.execute('SELECT SUM(total_amount) as total FROM sales').fetchone()['total'] or 0
    total_orders = cursor.execute('SELECT COUNT(*) as count FROM sales').fetchone()['count']
    low_stock = cursor.execute('SELECT COUNT(*) as count FROM products WHERE stock < 10').fetchone()['count']

    # Daily sales
    today_sales = cursor.execute('''
        SELECT SUM(total_amount) as total 
        FROM sales 
        WHERE DATE(created_at) = DATE('now')
    ''').fetchone()['total'] or 0

    # Monthly sales
    monthly_sales = cursor.execute('''
        SELECT SUM(total_amount) as total 
        FROM sales 
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    ''').fetchone()['total'] or 0

    conn.close()

    return render_template('admin_dashboard.html',
                           products=products,
                           staff_members=staff_members,
                           total_sales=total_sales,
                           total_orders=total_orders,
                           low_stock=low_stock,
                           today_sales=today_sales,
                           monthly_sales=monthly_sales)


@app.route('/staff/dashboard')
def staff_dashboard():
    if 'user_id' not in session or session.get('role') != 'staff':
        flash('Please login as staff first!', 'error')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Get products grouped by category
    products = cursor.execute('''
        SELECT * FROM products 
        ORDER BY category, name
    ''').fetchall()

    categories = cursor.execute('''
        SELECT DISTINCT category FROM products 
        ORDER BY category
    ''').fetchall()

    # Get today's orders for this staff
    today_orders = cursor.execute('''
        SELECT * FROM sales 
        WHERE staff_id = ? AND DATE(created_at) = DATE('now')
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()

    # Daily profit for this staff
    daily_profit = cursor.execute('''
        SELECT SUM(total_amount) as total 
        FROM sales 
        WHERE staff_id = ? AND DATE(created_at) = DATE('now')
    ''', (session['user_id'],)).fetchone()['total'] or 0

    # Monthly profit for this staff
    monthly_profit = cursor.execute('''
        SELECT SUM(total_amount) as total 
        FROM sales 
        WHERE staff_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    ''', (session['user_id'],)).fetchone()['total'] or 0

    conn.close()

    return render_template('staff_dashboard.html',
                           products=products,
                           categories=categories,
                           today_orders=today_orders,
                           daily_profit=daily_profit,
                           monthly_profit=monthly_profit)


@app.route('/admin/add_product', methods=['POST'])
def add_product():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    name = request.form['name']
    category = request.form['category']
    price = float(request.form['price'])
    stock = int(request.form['stock'])
    description = request.form.get('description', '')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO products (name, category, price, stock, description) VALUES (?, ?, ?, ?, ?)',
        (name, category, price, stock, description)
    )
    conn.commit()
    conn.close()

    flash('Product added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_product/<int:product_id>', methods=['POST'])
def edit_product(product_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    name = request.form['name']
    category = request.form['category']
    price = float(request.form['price'])
    stock = int(request.form['stock'])
    description = request.form.get('description', '')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE products SET name = ?, category = ?, price = ?, stock = ?, description = ? WHERE id = ?',
        (name, category, price, stock, description, product_id)
    )
    conn.commit()
    conn.close()

    flash('Product updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_product/<int:product_id>')
def delete_product(product_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()

    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_staff', methods=['POST'])
def add_staff():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    password_hash = generate_password_hash(password)

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (username, email, password_hash, 'staff')
        )
        conn.commit()
        conn.close()
        flash('Staff member added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Username or email already exists!', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle_staff/<int:staff_id>')
def toggle_staff(staff_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    user = cursor.execute('SELECT is_active FROM users WHERE id = ?', (staff_id,)).fetchone()
    new_status = 0 if user['is_active'] == 1 else 1
    cursor.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, staff_id))
    conn.commit()
    conn.close()

    flash('Staff status updated!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/sales')
def admin_sales():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    sales = cursor.execute('''
        SELECT s.*, u.username as staff_name 
        FROM sales s
        LEFT JOIN users u ON s.staff_id = u.id
        ORDER BY s.created_at DESC
    ''').fetchall()

    conn.close()

    return render_template('admin_sales.html', sales=sales)


@app.route('/staff/process_sale', methods=['POST'])
def staff_process_sale():
    if 'user_id' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))

    student_name = request.form.get('student_name', 'Walk-in Customer')
    payment_method = request.form['payment_method']

    conn = get_db()
    cursor = conn.cursor()

    products = cursor.execute('SELECT * FROM products').fetchall()

    selected_items = []
    total_amount = 0

    for product in products:
        qty_key = f'qty_{product["id"]}'
        quantity = int(request.form.get(qty_key, 0))

        if quantity > 0:
            if quantity > product['stock']:
                flash(f'Not enough stock for {product["name"]}!', 'error')
                conn.close()
                return redirect(url_for('staff_dashboard'))

            line_total = product['price'] * quantity
            selected_items.append({
                'id': product['id'],
                'name': product['name'],
                'price': product['price'],
                'quantity': quantity,
                'line_total': line_total
            })
            total_amount += line_total

    if not selected_items:
        flash('Please select at least one item!', 'error')
        conn.close()
        return redirect(url_for('staff_dashboard'))

    cursor.execute(
        'INSERT INTO sales (staff_id, student_name, payment_method, total_amount) VALUES (?, ?, ?, ?)',
        (session['user_id'], student_name, payment_method, total_amount)
    )
    sale_id = cursor.lastrowid

    for item in selected_items:
        cursor.execute(
            'INSERT INTO sale_items (sale_id, product_id, quantity, unit_price, line_total) VALUES (?, ?, ?, ?, ?)',
            (sale_id, item['id'], item['quantity'], item['price'], item['line_total'])
        )
        cursor.execute(
            'UPDATE products SET stock = stock - ? WHERE id = ?',
            (item['quantity'], item['id'])
        )

    conn.commit()
    conn.close()

    flash('Sale processed successfully!', 'success')
    return redirect(url_for('staff_dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)