# Auth System Server

Production-grade authentication service with session-based refresh tokens, secure cookies, input validation, and email flows.

## Folder Structure (Production)

```
server/
  .env               # Environment secrets (not committed)
  .env.example       # Sample env values
  package.json
  server.js          # Process bootstrap (connect DB, start app)
  config/
    db.js            # Mongo connection
    nodemailer.js    # SMTP transporter
  src/
    app.js           # Express app configuration & middlewares
    middlewares/
      error.js       # 404 + global error handler
    # Add more middlewares here (logging, compression)
  Routes/
    authRoutes.js    # Auth router with validation
  controller/
    authController.js# Controllers for auth endpoints
  models/
    usermodel.js     # User schema + session storage
  middleware/
    auth.js          # Access token auth guard
    validate.js      # Zod-based request validation
  validators/
    auth.js          # Zod schemas for auth endpoints
  utils/
    tokens.js        # Access/refresh token helpers
  postman/
    AuthSystem.postman_collection.json
    AuthSystem.postman_environment.json
```

## Environment Variables

See `.env.example` for all required variables:
- `PORT`, `NODE_ENV`
- `MONGO_URI`
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`
- `SMTP_USER`, `SMTP_PASS`, `SENDER_EMAIL`
- `CORS_ORIGIN` (comma-separated allowlist)

## Endpoints
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET  /api/auth/me` (requires `Authorization: Bearer <accessToken>`)
- `POST /api/auth/change-password` (auth)
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

## Run Locally

```powershell


npm install
npm run server
```

The server logs `Server started on Port: <PORT>` and `MongoDB Connected Successfully`.

## Postman
- Import collection: `postman/AuthSystem.postman_collection.json`
- Import environment: `postman/AuthSystem.postman_environment.json`
- Set environment `baseUrl` to `http://localhost:<PORT>`
- Run: Register/Login → Me → Refresh → Logout

## Notes
- Refresh cookie is `HttpOnly` + `Secure` in production, `SameSite=strict`.
- Access tokens are short-lived; use `/refresh` to rotate.
- Input validation via zod is enforced in routes.
- Add TLS termination at reverse proxy in production and set `NODE_ENV=production`.
