const express = require('express');
const mysql = require('mysql2');
const crypto = require('crypto');
const path = require('path');
const app = express();
const bcrypt = require('bcrypt');
const port = 3000;

// configures connection to MySQL
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  // password: 'your_mysql_password', // Replace 'your_mysql_password' with your actual MySQL root password
  database: 'admin_login',
  authPlugins: {
    mysql_clear_password: () => () => Buffer.from('your_mysql_password' + '\0')
  }
});

// creates database connection
connection.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database!');
});

// configures Express to parse JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// sets the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// creates routes
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/register', (req, res) => {
  res.render('register', { error: null, success: null });
});

app.post('/register', (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    res.render('register', { error: 'Please enter all the required fields', success: null });
    return;
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.render('register', { error: 'Error registering user', success: null });
      return;
    }

    const newUser = {
      first_name: firstName,
      last_name: lastName,
      email: email,
      password: hashedPassword
    };

    connection.query('INSERT INTO users SET ?', newUser, (err, result) => {
      if (err) {
        console.error('Error executing the MySQL query:', err);
        res.render('register', { error: 'Error registering user', success: null });
        return;
      }

      res.render('register', { success: 'User registered successfully!', error: null });
    });
  });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  console.log('Received form data:');
  console.log('Email:', email);
  console.log('Password:', password);

  if (!email || !password) {
    res.render('login', { error: 'Please enter both email and password' });
    return;
  }

  connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Error executing the MySQL query:', err);
      return;
    }

    if (results.length === 0) {
      res.render('login', { error: 'No account registered with this email or password' });
      return;
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) throw err;

      if (isMatch) {
        res.render('main', { users: results });
      } else {
        res.render('login', { error: 'No account registered with this email or password' });
      }
    });
  });
});

app.get('/main', (req, res) => {
  connection.query('SELECT * FROM users', (err, results) => {
    if (err) {
      console.error('Error executing the MySQL query:', err);
      return;
    }

    res.render('main', { users: results });
  });
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null });
});

// handles password reset form submission
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    res.render('forgot-password', { error: 'Please enter your email' });
    return;
  }

  // generates a unique reset code
  const resetCode = crypto.randomBytes(20).toString('hex');
  const resetExpiration = new Date(Date.now() + 3600000); // reset code valid for 1 hour

  // stores  reset code and its expiration time in the database
  connection.query(
    'UPDATE users SET reset_code = ?, reset_expiration = ? WHERE email = ?',
    [resetCode, resetExpiration, email],
    (err, result) => {
      if (err) {
        console.error('Error executing the MySQL query:', err);
        res.render('forgot-password', { error: 'Error sending reset code' });
        return;
      }

      // sends reset code to the user's email (implement this using a library like Nodemailer)
      console.log('Reset code:', resetCode);

      res.render('forgot-password', { success: 'Reset code sent to your email', error: null });
    }
  );
});

// renders  password reset page
app.get('/reset-password/:resetCode', (req, res) => {
  const resetCode = req.params.resetCode;

  // checks if reset code is valid and not expired
  connection.query('SELECT * FROM users WHERE reset_code = ? AND reset_expiration > ?', [resetCode, new Date()], (err, results) => {
    if (err) {
      console.error('Error executing the MySQL query:', err);
      res.render('login', { error: 'Error resetting password' });
      return;
    }

    if (results.length === 0) {
      res.render('login', { error: 'Invalid or expired reset code' });
      return;
    }

    res.render('reset-password', { resetCode: resetCode, error: null });
  });
});

// Handle the password reset page form submission
app.post('/reset-password/:resetCode', (req, res) => {
  const resetCode = req.params.resetCode;
  const newPassword = req.body.password;

  if (!newPassword) {
    res.render('reset-password', { resetCode: resetCode, error: 'Please enter a new password' });
    return;
  }

  // Hash the new password using bcrypt
  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.render('reset-password', { resetCode: resetCode, error: 'Error resetting password' });
      return;
    }

    // Update the user's password in the database
    connection.query('UPDATE users SET password = ?, reset_code = NULL, reset_expiration = NULL WHERE reset_code = ?', [hashedPassword, resetCode], (err, result) => {
      if (err) {
        console.error('Error executing the MySQL query:', err);
        res.render('reset-password', { resetCode: resetCode, error: 'Error resetting password' });
        return;
      }

      res.redirect('/login');
    });
  });
});

// starts server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
