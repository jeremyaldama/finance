import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    transacs = db.execute("SELECT t.symbol, t.name, SUM(t.shares) 'shares' FROM users u INNER JOIN transactionn t ON u.id = t.fid_user WHERE u.id = ? GROUP BY t.symbol, t.name HAVING SUM(t.shares) > 0;", session["user_id"])
    suma = 0.0
    for transac in transacs:
        s = lookup(transac["symbol"])
        transac["price"] = usd(s["price"])
        transac["total"] = int(transac["shares"]) * s["price"]
        suma += transac["total"]
        transac["total"] = usd(transac["total"])
    user[0]["total"] = usd(float(user[0]["cash"]) + suma)
    user[0]["cash"] = usd(user[0]["cash"])
    return render_template("index.html", transacs=transacs, user=user[0])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be a number")
        if shares < 1:
            return apology("Shars must be greater than 0")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        dic = lookup(request.form.get("symbol"))
        if not dic:
            return apology("INVALID SYMBOL")
        date = datetime.now()
        if cash[0]["cash"] < dic["price"]*shares:
            return apology("You don't have enough cash")
        db.execute("INSERT INTO transactionn(symbol, name, shares, price, date, fid_user) VALUES(?,?,?,?,?,?)",
                   dic["symbol"], dic["name"], shares, dic["price"], date.strftime('%Y-%m-%d %H:%M:%S'), session["user_id"])
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", dic["price"]*shares, session["user_id"])
        return redirect("/")

@app.route("/history")
@login_required
def history():
    transacs = db.execute("SELECT * FROM transactionn t WHERE fid_user = ?", session["user_id"])
    for transac in transacs:
        transac["price"] = usd(transac["price"])
    return render_template("history.html", transacs=transacs)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        dic = lookup(symbol)
        print(dic)
        if dic:
            dic["price"] = usd(dic["price"])
            return render_template("quoted.html", dic=dic)
        else:
            return apology("INVALID SYMBOL")
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username or not password or not confirmation:
            return apology("You must provide a username/password")
        if password != confirmation:
            return apology("Passwords don't match")
        if len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            return apology("The username is already taken")

        q = db.execute("INSERT INTO users(username, hash) VALUES(?,?);", username,
                generate_password_hash(password))
        # asignamos el id a la sesion
        session["user_id"] = q
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be a number greater than 0")

        if not symbol or symbol == "Symbol":
            return apology("You must select a symbol")

        dic = lookup(request.form.get("symbol"))
        symbol_d = db.execute("SELECT t.symbol, SUM(t.shares) 'shares' FROM users u INNER JOIN transactionn t ON u.id = t.fid_user WHERE u.id = ? AND t.symbol = ? GROUP BY t.symbol;", session["user_id"], symbol)
        if shares < 1:
            return apology("Shares must be greater than 0")
        if symbol_d[0]["shares"] < shares:
            return apology("You don't have enough shares to sell")
        else:
            date = datetime.now()
            db.execute("INSERT INTO transactionn(symbol, name, shares, price, date, fid_user) VALUES(?,?,?,?,?,?)",
                    dic["symbol"], dic["name"], -shares, dic["price"], date.strftime('%Y-%m-%d %H:%M:%S'), session["user_id"])
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", dic["price"]*shares, session["user_id"])
            return redirect("/")
    else:
        symbols = db.execute("SELECT t.symbol FROM users u INNER JOIN transactionn t ON u.id = t.fid_user WHERE u.id = ? GROUP BY t.symbol;", session["user_id"])
        return render_template("sell.html", symbols=symbols)
