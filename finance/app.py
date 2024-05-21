import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

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
    """Show portfolio of stocks"""
    id = session["user_id"]
    # symbol = db.execute("SELECT DISTINCT symbol FROM history WHERE user_id = ?", id)
    info = db.execute("SELECT * FROM w_?", id)
    arr = []
    sum = 0

    for i in range(len(info)):

        shares = int(info[i]["shares"])
        if shares == 0:
            continue

        symbol = info[i]["symbol"]
        price = float(lookup(symbol)["price"])
        total = price * shares
        sum += total

        tup = (symbol, shares, usd(price), usd(total))
        arr.append(tup)

    cash = float(db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"])
    total = usd(cash + sum)
    cash = usd(cash)

    db.execute(
        "UPDATE users SET net_worth = ? WHERE id = ?;", total, session["user_id"]
    )

    return render_template("index.html", arr=arr, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # get info
        symbol = request.form.get("symbol")
        info = lookup(symbol)
        if info == None:
            return apology("Invalid symbol")

        shares = request.form.get("shares")

        # is an int
        try:
            shares = int(shares)
        except ValueError:
            return apology("Invalid amount of shares")

        # is positive
        if not shares >= 1:
            return apology("Invalid amount of shares")

        # get values
        price = int(info["price"])
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = int(cash[0]["cash"])

        # check if they have enough money
        if cash < price:
            return apology("You are too broke")

        # Get the current date and time
        current_datetime = datetime.now()

        # Format it as a string in the format 'YYYY-MM-DD HH:MM:SS'
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        # Process transaction
        db.execute(
            "INSERT INTO history (user_id, transaction_type, symbol, price, shares, time) VALUES(?,?,?,?,?,?)",
            session["user_id"],
            "BUY",
            symbol,
            price,
            shares,
            formatted_datetime,
        )
        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?",
            price * shares,
            session["user_id"],
        )

        # checking if the user already has this stock
        tmp = db.execute(
            "SELECT symbol FROM w_? WHERE symbol = ?", session["user_id"], symbol
        )

        if not tmp:
            db.execute(
                "INSERT INTO w_? (symbol, shares) VALUES(?,?)",
                session["user_id"],
                symbol,
                shares,
            )
        else:
            # else
            db.execute(
                "UPDATE w_? SET shares = shares + ? WHERE symbol = ?",
                session["user_id"],
                shares,
                symbol,
            )

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    info = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])

    arr = []

    for i in range(len(info)):
        symbol = info[i]["symbol"]
        transaction_type = info[i]["transaction_type"]
        price = info[i]["price"]
        shares = info[i]["shares"]
        time = info[i]["time"]

        tup = (symbol, transaction_type, usd(price), shares, time)
        arr.append(tup)

    return render_template("history.html", arr=arr)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

        info = lookup(request.form.get("symbol"))

        # if invalid symbol
        if info == None:
            return apology("Invalid stock symbol")
        # redirect to quoted
        return render_template(
            "quoted.html", symbol=info["symbol"], price=usd(info["price"])
        )

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # username entered
        if not request.form.get("username"):
            return apology("must provide username")

        # password entered
        elif not request.form.get("password"):
            return apology("must provide password")

        # password confirm entered
        elif not request.form.get("confirmation"):
            return apology("must confirm password")

        password = request.form.get("password")
        username = request.form.get("username")

        # password same as Cpassword
        if password != request.form.get("confirmation"):
            return apology("passwords do not match")

        # username already exists

        exist_user = db.execute(
            "SELECT username FROM users WHERE username = ?", username
        )

        if exist_user:
            return apology("username already exists")

        # store in database
        else:
            # hash
            password = generate_password_hash(password, method="scrypt", salt_length=16)

            # insert
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)", username, password
            )

            # Remember which user has logged in
            result = db.execute("SELECT id FROM users WHERE username = ?", username)
            session["user_id"] = result[0]["id"]


            db.execute(
                "UPDATE users SET net_worth = cash WHERE id = ?;", session["user_id"]
            )

            # Create an empty table for the user
            db.execute(
                "CREATE TABLE w_? (symbol TEXT NOT NULL, shares INTEGER NOT NULL)",
                session["user_id"],
            )
            # Redirect user to home page
            return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # get info
        symbol = request.form.get("symbol")
        info = lookup(symbol)
        if info == None:
            return apology("Invalid symbol")

        shares = request.form.get("shares")

        # is an int
        try:
            shares = int(shares)
        except ValueError:
            return apology("Invalid amount of shares")

        # is positive
        if not shares >= 1:
            return apology("Invalid amount of shares")

        # checking if the user already has this stock)
        tmp = db.execute(
            "SELECT symbol FROM w_? WHERE symbol = ?", session["user_id"], symbol
        )

        if not tmp:
            return apology("You don't own this stock")

        # get values
        price = int(info["price"])
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = int(cash[0]["cash"])

        # check if user has enough shares
        user_shares = db.execute(
            "SELECT shares FROM w_? WHERE symbol = ?", session["user_id"], symbol
        )
        user_shares = int(user_shares[0]["shares"])

        if user_shares < shares:
            return apology("Not enough shares owned")

        # Get the current date and time
        current_datetime = datetime.now()

        # Format it as a string in the format 'YYYY-MM-DD HH:MM:SS'
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        # Process transaction
        db.execute(
            "INSERT INTO history (user_id, transaction_type, symbol, price, shares, time) VALUES(?,?,?,?,?,?)",
            session["user_id"],
            "SELL",
            symbol,
            price,
            shares,
            formatted_datetime,
        )
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            price * shares,
            session["user_id"],
        )

        db.execute(
            "UPDATE w_? SET shares = shares - ? WHERE symbol = ?",
            session["user_id"],
            shares,
            symbol,
        )

        return redirect("/")
    else:

        arr=[]
        symbols = db.execute("SELECT symbol FROM w_? WHERE shares > 0", session["user_id"])
        for i in range(len(symbols)):
            symbol = symbols[i]["symbol"]
            arr.append(symbol)

        return render_template("sell.html", arr=arr)


@app.route("/leaderboard")
@login_required
def leaderboard():
    """display leaderboard"""

    info = db.execute("SELECT username, net_worth FROM users ORDER BY net_worth DESC")
    arr = []

    for i in range(len(info)):
        username = info[i]["username"]
        net_worth = info[i]["net_worth"]
        rank = i + 1

        tup = (rank, username, net_worth)
        arr.append(tup)

    return render_template("leaderboard.html", arr=arr)
