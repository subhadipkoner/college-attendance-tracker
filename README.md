# College Attendance Tracker

Teachers take attendance for up to 8 periods a day, lock finished periods, and view day registers and reports.

* Netlify (hosting, serverless functions, Netlify Blobs storage)
* HTML, CSS and vanilla JavaScript front end (`public/index.html`)
* Node.js serverless API (`netlify/functions/api.mjs`)
* Server-side auth: scrypt password hashing, HttpOnly session cookies, login lockout

## How it works
- Anyone can create an account (name, email, password). Each account's sections, students and attendance are private to that account.
- 8 periods per day, optional subject per period, day register, reports and CSV export.
- A period can be locked once finished; the account that owns the data can unlock it.

## Deploy
Set the `SETUP_CODE` environment variable in Netlify (used only for owner password recovery), then deploy `public/` and `netlify/functions/`.

## Owner: reset a user's password
`POST /api/recover` with header `X-Attendance: 1` and JSON `{"setupCode": "<SETUP_CODE>", "username": "<email>", "password": "<new password>"}`.

## Opening `public/index.html` without a server
Falls back to browser-only storage (no sharing, no logins, no locking).
