const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false,
}));
app.use(express.static(path.join(__dirname, '../public')));

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your_email@gmail.com',      // <-- Use your real Gmail address
    pass: 'your_app_password',         // <-- Use a Gmail App Password
  },
});

// Database
const dbPath = path.join(__dirname, '../database/users.db');
const db = new sqlite3.Database(dbPath);

// Temporary store for 2FA codes
const twofaCodes = {};

/* Registration page */
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/register.html'));
});

/* Handle registration */
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email)
    return res.redirect('/feedback.html?title=Error&msg=All fields required.&link=/register');
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
    [username, hashedPassword, email],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE'))
          return res.redirect('/feedback.html?title=Error&msg=Username or email exists.&link=/register');
        return res.redirect('/feedback.html?title=Error&msg=Error registering user.&link=/register');
      }
      res.redirect('/feedback.html?title=Success&msg=Registration successful!&link=/login');
    }
  );
});

/* Login page */
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

/* Handle login and send 2FA code */
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      console.log('User not found or DB error:', err);
      return res.redirect('/feedback.html?title=Error&msg=Invalid username or password.&link=/login');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      console.log('Password mismatch');
      return res.redirect('/feedback.html?title=Error&msg=Invalid username or password.&link=/login');
    }

    // Generate 2FA code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    twofaCodes[username] = code;
    console.log(`2FA code for ${username}: ${code}`); // <-- This will show in your terminal

    // Send email with code
    transporter.sendMail({
      from: '"Cyber PT Site" <your_email@gmail.com>',
      to: user.email,
      subject: 'Your 2FA Code',
      text: `Your login code is: ${code}`,
    }, (err) => {
      if (err) {
        console.log('Error sending email:', err);
        return res.redirect('/feedback.html?title=Error&msg=Error sending 2FA code. Please try again.&link=/login');
      }
      req.session.pendingUser = username;
      res.redirect('/2fa');
    });
  });
});

/* 2FA page */
app.get('/2fa', (req, res) => {
  if (!req.session.pendingUser)
    return res.redirect('/feedback.html?title=Error&msg=Session expired. Please log in again.&link=/login');
  res.sendFile(path.join(__dirname, '../public/2fa.html'));
});

/* Handle 2FA code submission */
app.post('/2fa', (req, res) => {
  const { code } = req.body;
  const username = req.session.pendingUser;
  if (!username || !twofaCodes[username]) {
    return res.redirect('/feedback.html?title=Error&msg=Session expired. Please log in again.&link=/login');
  }
  if (code === twofaCodes[username]) {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      req.session.userId = user.id;
      delete req.session.pendingUser;
      delete twofaCodes[username];
      res.redirect('/feedback.html?title=Success&msg=2FA successful!&link=/');
    });
  } else {
    res.redirect('/feedback.html?title=Error&msg=Invalid code. Try again.&link=/2fa');
  }
});

/* Resend 2FA code route */
app.post('/resend-2fa', (req, res) => {
  const username = req.session.pendingUser;
  if (!username) return res.json({ message: 'Session expired. Please log in again.' });

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user) return res.json({ message: 'User not found.' });

    // Generate new code and send email
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    twofaCodes[username] = code;
    console.log(`Resent 2FA code for ${username}: ${code}`); // <-- This will show in your terminal
    transporter.sendMail({
      from: '"Cyber PT Site" <your_email@gmail.com>',
      to: user.email,
      subject: 'Your 2FA Code',
      text: `Your new 2FA code is: ${code}`
    }, (err) => {
      if (err) {
        console.log('Error sending email:', err);
        return res.json({ message: 'Failed to send code.' });
      }
      res.json({ message: 'A new code was sent to your email.' });
    });
  });
});

/* Logout route */
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/feedback.html?title=Success&msg=Logged out!&link=/');
  });
});

/* Home page */
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.sendFile(path.join(__dirname, '../public/profile.html'));
  } else {
    res.sendFile(path.join(__dirname, '../public/index.html'));
  }
});

/* Start the server */
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
