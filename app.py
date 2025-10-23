from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime, date

app = Flask(__name__)
app.secret_key = 'canteen_secret'


products = []
orders = []

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/login_user', methods=['POST'])
def login_user():
    username = request.form['username']
    password = request.form['password']

    if username == "admin" and password == "1234":
        session['username'] = username
        return redirect(url_for('staff_dashboard'))
    else:
        flash("Invalid username or password")
        return redirect(url_for('login_page'))

# STAFF DASHBOARD
@app.route('/staff/dashboard')
def staff_dashboard():
    if 'username' not in session:
        flash("Please log in first")
        return redirect(url_for('login_page'))

    today = date.today()

    daily_profit = sum(
        (o['total_price'] - (o['cost'] * o['quantity'])) for o in orders if o['date'] == today
    )
    monthly_profit = sum(
        (o['total_price'] - (o['cost'] * o['quantity'])) for o in orders if o['date'].month == today.month
    )

    return render_template(
        'staff_dashboard.html',
        user={'username': session['username']},  # Use logged-in username
        products=products,
        orders=[o for o in orders if o['date'] == today],
        daily_profit=round(daily_profit, 2),
        monthly_profit=round(monthly_profit, 2)
    )

@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form['name']
    category = request.form['category']
    price = float(request.form['price'])
    cost = float(request.form['cost'])
    stock = int(request.form['stock'])

    products.append({
        'name': name,
        'category': category,
        'price': price,
        'cost': cost,
        'stock': stock
    })
    return redirect(url_for('staff_dashboard'))

@app.route('/logout_user')
def logout_user():
    session.clear()
    return redirect(url_for('login_page'))

# STUDENT SHOP
@app.route('/shop')
def shop_page():
    categorized = {}
    for p in products:
        categorized.setdefault(p['category'], []).append(p)
    return render_template('student_shop.html', categorized=categorized)

@app.route('/checkout', methods=['POST'])
def checkout():
    selected_items = []
    total = 0

    for p in products:
        qty = int(request.form.get(p['name'], 0))
        if qty > 0 and p['stock'] >= qty:
            total_price = p['price'] * qty
            selected_items.append({'name': p['name'], 'price': p['price'], 'qty': qty, 'total': total_price, 'cost': p['cost']})
            p['stock'] -= qty
            total += total_price
            orders.append({
                'id': len(orders) + 1,
                'product_name': p['name'],
                'quantity': qty,
                'total_price': total_price,
                'cost': p['cost'],
                'order_time': datetime.now(),
                'date': date.today()
            })

    payment_method = request.form['payment']
    return render_template('checkout.html', items=selected_items, total=total, payment=payment_method)

if __name__ == '__main__':
    app.run(debug=True)
