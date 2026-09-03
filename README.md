# ChatBucket Business Admin Backend

Node.js/Express version of the admin API.

## Run

```bash
npm install
npm start
```

The server reads `MONGO_URL`, `DB_NAME`, `JWT_SECRET`, `HOST`, `PORT`, `ADMIN_EMAIL`,
`ADMIN_PASSWORD`, and `CMS_SCHEDULER_TICK_SECONDS` from `.env`.

Default URL: `http://localhost:8001/api`

Make sure MongoDB is running at the configured `MONGO_URL` before starting the API.
"# cb-superadmin-backend" 
