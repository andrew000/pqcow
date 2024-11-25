USERS_TABLE = """CREATE TABLE IF NOT EXISTS users
(
    id                   INTEGER   NOT NULL PRIMARY KEY AUTOINCREMENT,
    username             TEXT      NOT NULL COLLATE NOCASE UNIQUE,
    dilithium_public_key BLOB      NOT NULL UNIQUE,
    created_at           TIMESTAMP NOT NULL DEFAULT (datetime('now', 'utc'))
);
CREATE INDEX IF NOT EXISTS dilithium_public_key_index ON users
    (dilithium_public_key);
"""

CHATS_TABLE = """CREATE TABLE IF NOT EXISTS chats
(
    id                INTEGER   NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER   NOT NULL,
    chat_with_user_id INTEGER   NOT NULL,
    created_at        TIMESTAMP NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (chat_with_user_id) REFERENCES users (id),
    UNIQUE (user_id, chat_with_user_id)
);
CREATE INDEX IF NOT EXISTS chat_with_user_id_index ON chats
    (user_id);
"""

MESSAGES_TABLE = """CREATE TABLE IF NOT EXISTS messages
(
    message_id  INTEGER   NOT NULL PRIMARY KEY AUTOINCREMENT,
    chat_id     INTEGER   NOT NULL,
    sender_id   INTEGER   NOT NULL,
    receiver_id INTEGER   NOT NULL,
    message     TEXT      NOT NULL,
    signature   TEXT      NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (chat_id) REFERENCES chats (id),
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (receiver_id) REFERENCES users (id)
);
CREATE INDEX IF NOT EXISTS sender_id_index ON messages
    (sender_id);
"""
