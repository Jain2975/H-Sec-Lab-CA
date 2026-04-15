# SecureScope — SCODL Peer Code Review Tool

## Setup & Run

```bash
cd secure-review-app
npm install          # first time only (express, cors, multer)
node server.js       # starts on http://localhost:3000
```

Then open **http://localhost:3000** in your browser.

## What's inside

| File | Purpose |
|---|---|
| `server.js` | Express backend — serves static files + API routes |
| `public/index.html` | Full single-file frontend |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/experiments` | List all 9 experiments |
| GET | `/api/experiments/:id` | Full checklist + patterns for one experiment |
| POST | `/api/analyze` | Analyze pasted code (returns findings + score) |
| POST | `/api/reviews` | Save a completed review (in-memory) |
| GET | `/api/reviews` | List saved reviews |

## How to use for the CA

1. Select the experiment matching the code you're reviewing (Exp 1–9)
2. Paste your peer's code in the **Review** tab
3. Click **Run Automated Analysis** — it pattern-matches against known vulnerabilities
4. Switch to **Checklist** tab — left-click = PASS, right-click = FAIL
5. Write manual observations in the notes box
6. Go to **Findings** tab for the full scored report with fix recommendations
7. Hit **Save Report** and **Copy Checklist Summary** for your submission

## Experiments covered (all 9 from the SCODL folder)

1. Secure Programming Philosophy & Common Vulnerabilities
2. Robust Input Handling & Secure Validation  
3. Secure Code Review: Injection, Auth, Error Handling & Data Storage
4. Secure by Design: Least Privilege, Fail-Safe Defaults & Defense-in-Depth
5. Secure Login with Password Hashing & Salting
6. Secure Session Management & CSRF Protection
7. Secure Error Handling & Logging
8. Security Test Case Development (CIA Triad)
9. Secure Coding Maturity Assessment (OWASP / SSDF / OpenSAMM)
