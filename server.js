const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
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
    if (err) throw err;

    const newUser = {
      firstName: firstName,
      lastName: lastName,
      email: email,
      password: hashedPassword
    };

    connection.query('INSERT INTO users SET ?', newUser, (err, result) => {
      if (err) {
        console.error('Error executing the MySQL query:', err);
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
        res.redirect('/main');
      } else {
        res.render('login', { error: 'No account registered with this email or password' });
      }
    });
  });
});

app.get('/main', (req, res) => {
  // Fetch all users from the database
  connection.query('SELECT * FROM users', (err, results) => {
    if (err) {
      console.error('Error executing the MySQL query:', err);
      return;
    }

    // Render the 'main' view and pass the user data
    res.render('main', { users: results });
  });
});

// starts server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
