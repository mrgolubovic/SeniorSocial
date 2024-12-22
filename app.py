from flask import Flask, render_template, jsonify, session, redirect, flash, url_for, request
import sqlite3
import hashlib
import base64
import json
# from routes.api_routes import api_bp

app = Flask(__name__)

# Add a Jinja2 filter to encode binary data to Base64
@app.template_filter("b64encode")
def b64encode_filter(data):
    if data is None:
        return None
    return base64.b64encode(data).decode("utf-8")

app.secret_key = """
c5>btBWhG;vP,/f}ANmKn62w9][p~&g:a%#_yq4QD{Yk<('xzMAR~]EMw5)e8+6@39T:Hm"!f&<xNU,XSqD7y}LZGv2kd#=uQJ'zY`.Cpz%8:}u7'*LE]KFSyHb5r2Zw{cBhQVN=;v&-d+AT,qkWsmqg,um]>jr[`F_a6zketKQf+/<=B{s85!GT2wy^xUcX4$#b}n;J
"""  # Replace with a strong secret key

def get_db_connection():
    """Create a new database connection."""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def get_friends_and_requests(user_id):
    """Fetch friends and friend requests for the logged-in user."""
    conn = get_db_connection()
    try:
        friends = conn.execute("""
            SELECT users.username FROM friends
            JOIN users ON friends.friend_id = users.id
            WHERE friends.user_id = ? AND friends.status = 'accepted'
        """, (user_id,)).fetchall()

        friend_requests = conn.execute("""
            SELECT users.id, users.username FROM friends
            JOIN users ON friends.user_id = users.id
            WHERE friends.friend_id = ? AND friends.status = 'pending'
        """, (user_id,)).fetchall()  # Fix: Parameter wrapped as a tuple

        return friends, friend_requests
    finally:
        conn.close()


# 404 Error
@app.errorhandler(404)
def not_found(err):
    return render_template("404.html")
# Home Page
@app.route("/")
def index():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to view this page.")
        return redirect("/login")  # Redirect to login page if user is not logged in

    conn = get_db_connection()
    try:
        # Assuming user_id is the logged-in user's ID from session
        posts = conn.execute('''
        SELECT posts.id, posts.content, posts.created_at, users.username, users.id AS user_id
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.user_id IN (
            SELECT friend_id FROM friends WHERE user_id = ? AND status = 'accepted'
            UNION
            SELECT user_id FROM friends WHERE friend_id = ? AND status = 'accepted'
        )
        OR posts.user_id = ?
        ORDER BY posts.created_at DESC
    ''', (user_id, user_id, user_id)).fetchall()


        friends, friend_requests = get_friends_and_requests(user_id)
    finally:
        conn.close()

    return render_template("index.html", posts=posts, friends=friends, friend_requests=friend_requests)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE login_name = ? AND pass_hash = ?",
                (username, hashed_password)
            ).fetchone()

            if user:
                # Set session variables
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                app.logger.debug("User logged in, session: %s", session)
                flash("Login successful!", "success")
                return redirect("/")
            else:
                flash("Invalid username or password.", "error")
        finally:
            conn.close()

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        login_name = request.form["email"]
        password = request.form["password"]

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Handle profile photo upload
        profile_photo = request.files.get('profile_photo')
        if profile_photo and profile_photo.content_type.startswith('image/'):
            profile_photo_blob = profile_photo.read()
        else:
            profile_photo_blob = None  # Assign None if no valid photo is uploaded

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, login_name, pass_hash, profile_photo) VALUES (?, ?, ?, ?)",
                (username, login_name, hashed_password, profile_photo_blob)
            )
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Username or email already taken.", "error")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()  # Clear the session to log the user out
    flash("You have been logged out.", "success")
    return redirect(url_for('index'), 301)  # Redirect to the login page

@app.route("/create-post", methods=["GET", "POST"])
def create_post():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to create a post.")
        return redirect(url_for("login"))  # Redirect to login page if not logged in

    if request.method == "POST":
        content = request.form["content"]
        
        # Insert the new post into the database
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO posts (user_id, content)
            VALUES (?, ?)
        ''', (user_id, content))
        conn.commit()
        conn.close()

        flash("Your post has been created!", "success")
        return redirect(url_for("index"))  # Redirect to the home page or wherever you'd like

    return render_template("create-post.html")

@app.route("/my-profile")
def my_profile():
    return redirect(location=f"/profile?id={session.get('user_id')}", code=301)

@app.route("/profile")
def profile():
    """Fetch and display the user's profile, restricted to friends only."""
    user_id = request.args.get('id')  # Profile owner ID
    current_user_id = session.get('user_id')  # Logged-in user's ID

    # Check if the user is logged in
    if not current_user_id:
        flash("You need to log in to view profiles.", "error")
        return redirect(url_for('login'))

    # Validate and convert user_id
    if not user_id:
        flash("Profile ID is missing.", "error")
        return redirect(url_for('index'))
    
    try:
        user_id = int(user_id)
    except ValueError:
        flash("Invalid profile ID.", "error")
        return redirect(url_for('index'))

    # Database operations
    with get_db_connection() as conn:
        # Check if the profile belongs to a friend or the user themselves
        is_friend_query = '''
            SELECT COUNT(*)
            FROM friends
            WHERE (
                (user_id = ? AND friend_id = ?)
                OR (user_id = ? AND friend_id = ?)
            ) AND status = 'accepted'
        '''
        is_friend = conn.execute(is_friend_query, 
                                 (current_user_id, user_id, user_id, current_user_id)).fetchone()
        is_friend = is_friend[0] if is_friend else 0

        if not is_friend and user_id != current_user_id:
            flash("You can only view your friends' profiles.", "error")
            return redirect(url_for('index'))

        # Fetch the profile data
        user_query = "SELECT id, username, profile_photo FROM users WHERE id = ?"
        user = conn.execute(user_query, (user_id,)).fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('index'))

        # Fetch the user's friends
        friends_query = '''
            SELECT DISTINCT users.id, users.username, users.profile_photo
            FROM friends
            JOIN users ON users.id = CASE
            WHEN friends.user_id = ? THEN friends.friend_id
            WHEN friends.friend_id = ? THEN friends.user_id
            END
            WHERE (friends.user_id = ? OR friends.friend_id = ?) AND friends.status = 'accepted'
        '''
        friends = conn.execute(friends_query, (user_id, user_id, user_id, user_id)).fetchall()

        # Fetch the user's posts
        posts_query = '''
            SELECT content, created_at, id
            FROM posts 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        '''
        posts = conn.execute(posts_query, (user_id,)).fetchall()

    return render_template("profile.html", user=user, friends=friends, posts=posts, session_id=int(session.get('user_id')))


@app.route("/friend-action", methods=["POST"])
def friend_action():
    """Handle friend actions (accept, reject, unfriend)."""
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to perform this action.", "error")
        return redirect(url_for("login"))

    action = request.form.get("action")
    friend_id = request.form.get("friend_id")

    conn = get_db_connection()
    try:
        if action == "accept":
            # Accept friend request
            conn.execute('''
                UPDATE friends SET status = 'accepted'
                WHERE user_id = ? AND friend_id = ?
            ''', (friend_id, user_id))
        elif action == "reject":
            # Reject friend request
            conn.execute('''
                DELETE FROM friends
                WHERE user_id = ? AND friend_id = ?
            ''', (friend_id, user_id))
        elif action == "unfriend":
            # Remove friendship (both directions)
            conn.execute('''
                DELETE FROM friends
                WHERE (user_id = ? AND friend_id = ?) OR 
                      (user_id = ? AND friend_id = ?)
            ''', (user_id, friend_id, friend_id, user_id))
        conn.commit()
    finally:
        conn.close()

    flash("Friend action completed successfully!", "success")
    return redirect(url_for("profile", id=user_id))

@app.route("/friend-manage", methods=["POST"])
def friend_manage():
    """Handle actions related to friends, like accepting, rejecting, or unfriending."""
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to perform this action.", "error")
        return redirect(url_for("login"))

    action = request.form.get("action")  # Action to be performed (accept, reject, unfriend)
    friend_id = request.form.get("friend_id")  # The ID of the friend being managed

    if not action or not friend_id:
        flash("Invalid action or friend ID.", "error")
        return redirect(url_for("index"))

    conn = get_db_connection()
    try:
        if action == "accept":
            # Accept friend request
            conn.execute('''
                UPDATE friends
                SET status = 'accepted'
                WHERE user_id = ? AND friend_id = ?
            ''', (friend_id, user_id))

            conn.execute('''
                INSERT INTO friends (user_id, friend_id, status)
                VALUES (?, ?, 'accepted')
            ''', (user_id, friend_id))  # Add the reverse friendship if not already present

            flash(f"You and {friend_id} are now friends!", "success")

        elif action == "reject":
            # Reject friend request
            conn.execute('''
                DELETE FROM friends
                WHERE user_id = ? AND friend_id = ?
            ''', (friend_id, user_id))

            flash(f"You rejected the friend request from {friend_id}.", "info")

        elif action == "unfriend":
            # Unfriend the user (both directions)
            conn.execute('''
                DELETE FROM friends
                WHERE (user_id = ? AND friend_id = ?) OR 
                      (user_id = ? AND friend_id = ?)
            ''', (user_id, friend_id, friend_id, user_id))

            flash(f"You unfriended {friend_id}.", "info")

        conn.commit()

    except Exception as e:
        conn.rollback()
        flash(f"An error occurred: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for("index"))  # Redirect to the homepage or another page as needed
@app.route('/friends', methods=['GET', 'POST'])
def friend_management():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to manage your friends.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()

    if request.method == 'POST':
        # Handle Add Friend Request
        if 'username' in request.form:
            username = request.form['username']
            # Check if user exists
            user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if user:
                # Insert the friend request
                conn.execute('''
                    INSERT INTO friends (user_id, friend_id, status)
                    VALUES (?, ?, ?)
                ''', (user_id, user['id'], 'pending'))
                conn.commit()
                flash("Friend request sent!", "success")
            else:
                flash("User not found.", "error")

        # Handle Accept Friend Request
        elif 'accept_friend_request' in request.form:
            request_id = request.form['accept_friend_request']
            # Update the request status to 'accepted'
            conn.execute('''
                UPDATE friends 
                SET status = 'accepted' 
                WHERE request_id = ? AND friend_id = ?
            ''', (request_id, user_id))
            conn.commit()
            flash("Friend request accepted!", "success")

        # Handle Decline Friend Request
        elif 'decline_friend_request' in request.form:
            request_id = request.form['decline_friend_request']
            # Delete the request from the friends table
            conn.execute('''
                DELETE FROM friends 
                WHERE request_id = ?
            ''', (request_id,))
            conn.commit()
            flash("Friend request declined.", "error")

        # Handle Remove Friend
        elif 'remove_friend' in request.form:
            friend_id = request.form['remove_friend']
            conn.execute('''
                DELETE FROM friends 
                WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
            ''', (user_id, friend_id, friend_id, user_id))
            conn.commit()
            flash("Friend removed!", "success")

    # Get the list of friends (accepted status)
    friends = conn.execute('''
        SELECT u.id, u.username, u.profile_photo
        FROM users u
        JOIN friends f ON (f.user_id = u.id OR f.friend_id = u.id)
        WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'accepted'
    ''', (user_id, user_id)).fetchall()

    # Get the pending friend requests
    pending_requests = conn.execute('''
    SELECT r.request_id, u.username
    FROM friends r
    JOIN users u ON r.user_id = u.id
    WHERE r.friend_id = ? AND r.status = 'pending'
''', (user_id,)).fetchall()

    conn.close()
    return render_template('friends_manage.html', friends=friends, pending_requests=pending_requests)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    conn = get_db_connection()

    # Fetch the post to verify existence and ownership
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if not post:
        conn.close()
        flash("Post not found.", "error")
        return redirect(url_for('index'))

    if post["user_id"] != session.get("user_id"):
        conn.close()
        flash("You don't have permission to delete this post.", "error")
        return redirect(url_for('index'))

    # Perform the delete operation
    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()  # Commit changes to the database
    conn.close()

    flash("Post deleted successfully.", "success")
    return redirect(url_for('index'))

@app.route('/news')
def news():
    conn = get_db_connection()
    articles = conn.execute("SELECT * FROM articles ORDER BY published_date DESC").fetchall()
    conn.close()
    return render_template("news.html", articles=articles)

@app.route('/article', methods=['GET'])
def article():
    conn = get_db_connection()
    articleId = int(request.args.get('id', 0))
    if articleId == 0:
        return redirect(url_for('index'))
    article = conn.execute("SELECT * FROM articles WHERE id = ?", (articleId,)).fetchone()
    if article is None:
        return redirect(url_for('index'))
    return render_template("article.html", article=article)

@app.route("/remove_friend", methods=["POST"])
def remove_friend():
    """Remove a friend relationship."""
    if not session.get("user_id"):
        flash("You need to log in to manage friends.", "error")
        return redirect(url_for("login"))

    # Get the current user's ID and the friend's ID
    current_user_id = int(session.get("user_id"))
    friend_id = request.form.get("friend_id")

    # Validate friend_id
    try:
        friend_id = int(friend_id)
    except (ValueError, TypeError):
        flash("Invalid friend ID.", "error")
        return redirect(url_for("profile", id=current_user_id))

    with get_db_connection() as conn:
        # Check if the friendship exists
        friendship = conn.execute('''
            SELECT COUNT(*) 
            FROM friends 
            WHERE (
                (user_id = ? AND friend_id = ?)
                OR (user_id = ? AND friend_id = ?)
            ) AND status = 'accepted'
        ''', (current_user_id, friend_id, friend_id, current_user_id)).fetchone()

        if not friendship or friendship[0] == 0:
            flash("Friendship does not exist.", "error")
            return redirect(url_for("profile", id=current_user_id))

        # Delete the friendship
        conn.execute('''
            DELETE FROM friends 
            WHERE (user_id = ? AND friend_id = ?)
            OR (user_id = ? AND friend_id = ?)
        ''', (current_user_id, friend_id, friend_id, current_user_id))
        conn.commit()

    flash("Friend removed successfully.", "success")
    return redirect(url_for("profile", id=current_user_id))
    
if __name__ == "__main__":
    app.run(debug=True)
