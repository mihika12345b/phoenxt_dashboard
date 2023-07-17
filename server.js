const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

// configures connection to MySQL
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
//  password: 'your_mysql_password', // Replace 'your_mysql_password' with your actual MySQL root password
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

// creates routes
app.get('/', (req, res) => {
  res.redirect('/register');
});

app.get('/register', (req, res) => {
  res.render('register', { error: null, success: null });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.render('register', { error: 'Please enter both username and password', success: null });
    return;
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) throw err;

    const newUser = {
      username: username,
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

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  console.log('Received form data:');
  console.log('Username:', username);
  console.log('Password:', password);

  if (!username || !password) {
    res.render('index', { error: 'Please enter both username and password' });
    return;
  }

  connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error executing the MySQL query:', err);
      return;
    }

    if (results.length === 0) {
      res.render('index', { error: 'Invalid username or password' });
      return;
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) throw err;

      if (isMatch) {
        res.render('dashboard', { username: user.username });
      } else {
        res.render('index', { error: 'Invalid username or password' });
      }
    });
  });
});

// starts server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});