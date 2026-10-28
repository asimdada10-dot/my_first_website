# Dada Footwear Maintenance Management (v3 - server-backed)

Your original single-file UI, now backed by a real server: SQLite database, scrypt password hashing,
server-side permissions, audit log, validated uploads. **No npm packages needed** (Node 22.13+).

## Run
    node -v                       # must be >= 22.13
    cp .env.example .env          # then export the variables (or set them in your service manager)
    ADMIN_PASSWORD='a-long-password' SEED_EXAMPLE=true node server.js
    # open http://localhost:3000 and sign in as admin
If ADMIN_PASSWORD is not set, a random password is printed once on first start. Nothing is hardcoded.

## Test
    npm test      # 37 API acceptance tests on a temporary database

## Deploy (Linux server)
1. Install Node 22+, copy this folder to /opt/dada, create a `dada` user.
2. systemd unit: `ExecStart=/usr/bin/node server.js`, `Environment=PORT=3000 DATA_DIR=/var/lib/dada COOKIE_SECURE=true`, `Restart=always`.
3. Put nginx/Caddy in front with HTTPS (Let's Encrypt) and proxy to 127.0.0.1:3000. Do not expose port 3000 directly.
4. Nightly backup (cron): `DATA_DIR=/var/lib/dada node server.js backup /backups/dada-$(date +%F).db`
5. Restore (stop the service first): `node server.js restore /backups/dada-2026-10-28.db`
   Also copy `$DATA_DIR/uploads/` (photos) with your backups.

## Schema (SQLite, data/app.db)
users(id, username UNIQUE, full_name, emp_id, contact, department, hall, role, status, perms JSON|NULL, photo, pw scrypt-hash)
sessions(h sha256-of-token, user_id, exp) | records(res, id, data JSON, created_by, updated_by, updated_at) PK(res,id)
settings(k, v JSON) | audit(id, ts, user, action, detail)
`records.res` = machines, orders, preventive, spares, team, movements (stock history, written by server only).

## API (all JSON, cookie session, `X-Requested-With: df` required on writes)
POST /api/login, /api/logout | GET /api/me | GET/PUT /api/settings | GET /api/audit
GET/POST /api/users, PUT/DELETE /api/users/:id (?confirm=username) | GET/POST /api/r/:res, PUT/DELETE /api/r/:res/:id
POST /api/upload (raw image, <=2 MB, magic-byte checked) | GET /api/backup | POST /api/import

## Permissions
`<resource>.<view|add|edit|delete|export>` plus users.*, settings.view/edit, audit.view, backup.export/import.
Roles give defaults; a user can instead get a custom list. Every request re-reads the user from the database,
so disabling/deleting/changing permissions takes effect immediately. Only a Super Admin can manage Admin accounts;
nobody can grant permissions they don't hold; the last Super Admin can't be removed.

## Not done yet / limitations
See the list in the chat summary. Run behind HTTPS; the CSP still allows inline scripts because the original UI uses inline handlers.
