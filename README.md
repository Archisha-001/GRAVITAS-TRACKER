# GraviTrack - local version

This version uses a tiny Node.js local server and one local JSON file for accounts. There is **no cloud database** and no Express, JWT, SQLite, or other npm package to install.

## Run on Windows

1. Install Node.js 18+.
2. Extract this folder.
3. Double-click `start-gravitrack.bat`.
4. Your browser should open automatically at `http://localhost:4000`.

You can also open a terminal in this folder and run:

```bash
node server.js
```

Then visit:

```text
http://localhost:4000
```

## Local storage

Accounts are stored in:

```text
data/users.json
```

Passwords are hashed with Node's built-in `crypto.scryptSync`; plaintext passwords are never saved.

## Important

Do **not** double-click `public/index.html` for the local-backend version. Use the local URL served by Node so the login/signup API is available.
