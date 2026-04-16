import express from "express";
import helmet from "helmet";
import bcrypt from "bcrypt";
import csrf from "csurf";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import fs from "fs";
import cors from "cors";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const isProd = process.env.NODE_ENV === "production";

// In-memory session store for demo
const sessions = new Map();

// In-memory book store (for demo)
let books = [
  { id: 1, title: "Clean Code", author: "Robert Martin" },
  { id: 2, title: "The Pragmatic Programmer", author: "Andrew Hunt" },
   {id: 3, title: "Ikigai" , author: "Some Japanese Man" },
];

// 1. SECURITY MIDDLEWARE
app.use(
  helmet({
    // Disable strict CSP for this demo so React dev server works easily
    contentSecurityPolicy: false,
  }),
);

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:5173", 
    credentials: true,
  }),
);

// Serve static files (if you ever want to serve built frontend from Express)
app.use(express.static(__dirname));

// 2. RATE LIMITING (login brute-force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later." },
});

// 3. SECURE LOGGING FUNCTION (Exp 7: no stack traces to client)
function secureLog(action, username, details = {}) {
  const timestamp = new Date().toISOString();
  const safeUser =
    typeof username === "string"
      ? username.replace(/[^\w@.-]/g, "")
      : "anonymous";

  // Mask username: first char + *** + last char
  const masked =
    safeUser.length > 2
      ? safeUser[0] + "***" + safeUser[safeUser.length - 1]
      : "***";

  const logObj = {
    timestamp,
    action,
    user: masked,
    ip: details.ip || "unknown",
    success: details.success ?? null,
    message: details.message || "",
    // Do NOT log passwords, tokens, or full sessions
  };

  const line = JSON.stringify(logObj) + "\n";

  // Append to logs.txt (async in production; sync is okay for demo)
  fs.appendFile("logs.txt", line, (err) => {
    if (err) {
      // If logging fails, don’t crash; just console on server side
      console.error("Logging failed:", err.message);
    }
  });
}

// 4. INPUT VALIDATION (Exp 2: whitelist)
function validateUsername(input) {
  return /^[a-zA-Z0-9_]{3,20}$/.test(input);
}

function validatePassword(input) {
  return typeof input === "string" && input.length >= 8 && input.length <= 64;
}

function validateBookTitle(title) {
  return (
    typeof title === "string" &&
    title.trim().length >= 2 &&
    title.trim().length <= 150
  );
}

function validateBookAuthor(author) {
  return (
    typeof author === "string" &&
    author.trim().length >= 2 &&
    author.trim().length <= 150
  );
}

// 5. CSRF PROTECTION
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: isProd,
  },
});

// Dummy bcrypt hash for timing-consistent user enumeration defense
const DUMMY_HASH =
  "$2b$12$6UzMDM.H6dfI/f/IKcEehuJd6OF6eRuK1D7ton0tVvMLFpJh6i8rK";

// MOCK USERS
let users = [
  {
    id: 1,
    username: "admin",
    password: await bcrypt.hash("admin123", 12),
  },
];

// Auth middleware
function requireAuth(req, res, next) {
  const sid = req.cookies.session;
  if (!sid || !sessions.has(sid)) {
    secureLog("ACCESS_DENIED", req.body?.username || "unknown", {
      success: false,
      message: "Unauthorized access attempt",
      ip: req.ip,
    });
    return res.status(403).json({ error: "Access Denied: Please log in." });
  }
  req.user = sessions.get(sid);
  next();
}

// 6. ROUTES

// Get CSRF token
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ token: req.csrfToken() });
});

app.post("/api/login", loginLimiter, csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  try {
    // Validate input 
    if (!validateUsername(username) || !validatePassword(password)) {
      secureLog("LOGIN_MALFORMED", username || "unknown", {
        success: false,
        message: "Malformed input",
        ip: req.ip,
      });
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const user = users.find((u) => u.username === username);

    // Timing-constant user enumeration defense 
    if (!user) {
      await bcrypt.compare("dummy_password", DUMMY_HASH);
      secureLog("LOGIN_FAIL_USER_NOT_FOUND", username, {
        success: false,
        message: "User not found",
        ip: req.ip,
      });
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      secureLog("LOGIN_FAIL_WRONG_PASSWORD", username, {
        success: false,
        message: "Wrong password",
        ip: req.ip,
      });
      return res.status(401).json({ error: "Invalid credentials." });
    }

    // Create server-side session 
    const sessionId = crypto.randomBytes(32).toString("hex");
    sessions.set(sessionId, {
      userId: user.id,
      username: user.username,
      createdAt: Date.now(),
    });

    res.cookie("session", sessionId, {
      httpOnly: true,
      sameSite: "strict",
      secure: isProd,
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    secureLog("LOGIN_SUCCESS", username, {
      success: true,
      message: "Login successful",
      ip: req.ip,
    });

    res.json({ message: "Access Granted.", user: { username: user.username } });
  } catch (err) {
    // Do not leak stack trace 
    console.error("Login error");
    secureLog("LOGIN_ERROR", username || "unknown", {
      success: false,
      message: "Internal error",
      ip: req.ip,
    });
    res.status(500).json({ error: "Internal System Error" });
  }
});

// LOGOUT
app.post("/api/logout", requireAuth, csrfProtection, (req, res) => {
  const sid = req.cookies.session;
  const user = req.user;

  sessions.delete(sid);
  res.clearCookie("session");

  secureLog("LOGOUT", user.username, {
    success: true,
    message: "Logout successful",
    ip: req.ip,
  });

  res.json({ message: "Logged out successfully." });
});

// VIEW BOOKS (requires auth)
app.get("/api/books", requireAuth, (req, res) => {
  secureLog("VIEW_BOOKS", req.user.username, {
    success: true,
    message: "Listed books",
    ip: req.ip,
  });
  res.json({ books });
});
//OLD

// // ADD BOOK (requires auth + CSRF)
// app.post("/api/books", requireAuth, csrfProtection, (req, res) => {
//   const { title, author } = req.body;
//   const user = req.user;

//   if (!validateBookTitle(title) || !validateBookAuthor(author)) {
//     secureLog("ADD_BOOK_INVALID_INPUT", user.username, {
//       success: false,
//       message: "Invalid book data",
//       ip: req.ip,
//     });
//     return res.status(400).json({ error: "Invalid book data." });
//   }

//   const newBook = {
//     id: books.length > 0 ? Math.max(...books.map((b) => b.id)) + 1 : 1,
//     title: title.trim(),
//     author: author.trim(),
//   };

//   books.push(newBook);

//   secureLog("ADD_BOOK", user.username, {
//     success: true,
//     message: `Added book: ${newBook.title}`,
//     ip: req.ip,
//   });

//   res.status(201).json({ message: "Book added.", book: newBook });
// });

// ADD BOOK (requires auth + CSRF)
app.post("/api/books", requireAuth, csrfProtection, (req, res) => {
  const { title, author } = req.body;
  const user = req.user;

  if (!validateBookTitle(title) || !validateBookAuthor(author)) {
    return res.status(400).json({ error: "Invalid book data." });
  }

  
  const nextId = books.length === 0 
    ? 1 
    : Math.max(...books.map(b => b.id)) + 1;

  const newBook = {
    id: nextId,
    title: title.trim(),
    author: author.trim(),
  };

  books.push(newBook);
  
  secureLog("ADD_BOOK", user.username, {
    success: true,
    message: `Added book: ${newBook.title}`,
    ip: req.ip,
  });

  res.status(201).json({ message: "Book added.", book: newBook });
});

//OLD
// DELETE BOOK (requires auth + CSRF)
// app.delete("/api/books/:id", requireAuth, csrfProtection, (req, res) => {
//   const id = parseInt(req.params.id, 10);
//   const user = req.user;

//   const idx = books.findIndex((b) => b.id === id);
//   if (idx === -1) {
//     secureLog("DELETE_BOOK_NOT_FOUND", user.username, {
//       success: false,
//       message: `Book ID ${id} not found`,
//       ip: req.ip,
//     });
//     return res.status(404).json({ error: "Book not found." });
//   }

//   const deletedBook = books.splice(idx, 1)[0];

//   secureLog("DELETE_BOOK", user.username, {
//     success: true,
//     message: `Deleted book: ${deletedBook.title}`,
//     ip: req.ip,
//   });

//   res.json({ message: "Book deleted.", book: deletedBook });
// });


app.delete("/api/books/:id", requireAuth, csrfProtection, (req, res) => {
  const id = parseInt(req.params.id, 10);
  
  if (isNaN(id)) {
    return res.status(400).json({ error: "Invalid Book ID format." });
  }

  const user = req.user;
  const idx = books.findIndex((b) => b.id === id);  
  
  if (idx === -1) {
    secureLog("DELETE_BOOK_NOT_FOUND", user.username, {
      success: false,
      message: `Book ID ${id} not found`,
      ip: req.ip,
    });
    return res.status(404).json({ error: "Book not found." });
  }

  const deletedBook = books.splice(idx, 1)[0];

  secureLog("DELETE_BOOK", user.username, {
    success: true,
    message: `Deleted book: ${deletedBook.title}`,
    ip: req.ip,
  });

  res.json({ message: "Book deleted.", book: deletedBook });
});

// Start server
app.listen(PORT, () => {
  console.log(`Secure library server running on http://localhost:${PORT}`);
  secureLog("SERVER_START", "system", {
    success: true,
    message: `Server started on port ${PORT}`,
    ip: "localhost",
  });
});
