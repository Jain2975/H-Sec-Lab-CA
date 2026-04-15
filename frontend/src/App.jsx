import { useState, useEffect } from "react";
import "./App.css";

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [loggedIn, setLoggedIn] = useState(false);
  const [userInfo, setUserInfo] = useState(null);

  const [books, setBooks] = useState([]);
  const [bookTitle, setBookTitle] = useState("");
  const [bookAuthor, setBookAuthor] = useState("");

  const [msg, setMsg] = useState("");
  const [msgType, setMsgType] = useState(""); // 'success' | 'error' | ''

  const [loading, setLoading] = useState(false);

  // Fetch CSRF token on mount
  useEffect(() => {
    fetchCsrfToken();
    // Check if already logged in by trying to load books
    checkAuth();
  }, []);

  async function fetchCsrfToken() {
    try {
      const res = await fetch("/api/csrf-token", { credentials: "include" });
      if (!res.ok) return;
      const data = await res.json();
      setCsrfToken(data.token);
    } catch {
      // ignore
    }
  }

  async function checkAuth() {
    try {
      const res = await fetch("/api/books", { credentials: "include" });
      if (!res.ok) {
        setLoggedIn(false);
        setUserInfo(null);
        return;
      }
      const data = await res.json();
      setLoggedIn(true);
      setBooks(data.books || []);
    } catch {
      setLoggedIn(false);
    }
  }

  function showMessage(text, type = "") {
    setMsg(text);
    setMsgType(type);
  }

  async function handleLogin(e) {
    e.preventDefault();
    if (!username || !password) {
      showMessage("Username and password are required.", "error");
      return;
    }

    setLoading(true);
    showMessage("Authenticating...", "");

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();
      if (res.ok) {
        showMessage("Access Granted.", "success");
        setLoggedIn(true);
        setUserInfo(data.user);
        await loadBooks();
      } else {
        showMessage(data.error || "Login failed.", "error");
      }
    } catch {
      showMessage("Network error. Try again.", "error");
    } finally {
      setLoading(false);
    }
  }

  async function loadBooks() {
    try {
      const res = await fetch("/api/books", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) {
        setBooks([]);
        return;
      }
      setBooks(data.books || []);
    } catch {
      setBooks([]);
    }
  }

  async function handleAddBook(e) {
    e.preventDefault();
    if (!bookTitle.trim() || !bookAuthor.trim()) {
      showMessage("Title and author are required.", "error");
      return;
    }

    try {
      const res = await fetch("/api/books", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        credentials: "include",
        body: JSON.stringify({
          title: bookTitle,
          author: bookAuthor,
        }),
      });

      const data = await res.json();
      if (res.ok) {
        showMessage(`Book "${data.book.title}" added.`, "success");
        setBookTitle("");
        setBookAuthor("");
        await loadBooks();
      } else {
        showMessage(data.error || "Failed to add book.", "error");
      }
    } catch {
      showMessage("Network error. Could not add book.", "error");
    }
  }

  async function handleDeleteBook(id, title) {
    if (!window.confirm(`Delete "${title}"?`)) return;

    try {
      const res = await fetch(`/api/books/${id}`, {
        method: "DELETE",
        headers: {
          "X-CSRF-Token": csrfToken,
        },
        credentials: "include",
      });

      const data = await res.json();
      if (res.ok) {
        showMessage(`Book "${title}" deleted.`, "success");
        await loadBooks();
      } else {
        showMessage(data.error || "Failed to delete book.", "error");
      }
    } catch {
      showMessage("Network error. Could not delete book.", "error");
    }
  }

  async function handleLogout() {
    try {
      await fetch("/api/logout", {
        method: "POST",
        headers: {
          "X-CSRF-Token": csrfToken,
        },
        credentials: "include",
      });
    } catch {
      // ignore
    } finally {
      setLoggedIn(false);
      setUserInfo(null);
      setBooks([]);
      showMessage("Logged out.", "success");
    }
  }

  return (
    <div className="App">
      <h1>Book Manager</h1>

      {msg && <div className={`message ${msgType}`}>{msg}</div>}

      {!loggedIn ? (
        <form onSubmit={handleLogin} className="login-form">
          <h2>Login</h2>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={loading}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={loading}
          />
          <button type="submit" disabled={loading}>
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>
      ) : (
        <div className="book-manager">
          <div className="header">
            <h2>Welcome, {userInfo.username}</h2>
            <button onClick={handleLogout}>Logout</button>
          </div>

          <form onSubmit={handleAddBook} className="add-book-form">
            <h3>Add a New Book</h3>
            <input
              type="text"
              placeholder="Title"
              value={bookTitle}
              onChange={(e) => setBookTitle(e.target.value)}
            />
            <input
              type="text"
              placeholder="Author"
              value={bookAuthor}
              onChange={(e) => setBookAuthor(e.target.value)}
            />
            <button type="submit">Add Book</button>
          </form>

          <h3>Book List</h3>
          {books.length === 0 ? (
            <p>No books available.</p>
          ) : (
            <ul className="book-list">
              {books.map((book) => (
                <li key={book.id}>
                  <strong>{book.title}</strong> by {book.author}
                  <button
                    className="delete-btn"
                    onClick={() => handleDeleteBook(book.id, book.title)}
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
