CREATE TABLE IF NOT EXISTS articles (
id INTEGER PRIMARY KEY AUTOINCREMENT,
title TEXT NOT NULL,
content TEXT NOT NULL,
author TEXT,
published_date DATETIME DEFAULT CURRENT_TIMESTAMP,
category TEXT,
image_url TEXT,
source_url TEXT
);

CREATE TABLE IF NOT EXISTS friends (
request_id INTEGER PRIMARY KEY,
user_id INTEGER NOT NULL,
friend_id INTEGER NOT NULL,
status TEXT DEFAULT 'pending',
FOREIGN KEY(user_id) REFERENCES users(id),
FOREIGN KEY(friend_id) REFERENCES users(id)
);
CREATE INDEX idx_friends_user_id ON friends (user_id);
CREATE INDEX idx_friends_friend_id ON friends (friend_id);

CREATE TABLE IF NOT EXISTS posts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
content TEXT NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, likes INTEGER DEFAULT 0,
FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX idx_posts_user_id ON posts (user_id);

CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE NOT NULL,
login_name TEXT UNIQUE NOT NULL,
pass_hash TEXT NOT NULL,
profile_photo BLOB
);