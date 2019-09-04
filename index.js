const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcryptjs = require('bcryptjs')

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  console.log('pass arriving from client', user.password)

  user.password = bcryptjs.hashSync(user.password, 10)//runs 2 to the power of 10x's

  console.log('pass to db', user.password)
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// Should be protected
// req.headers should have a correct username/password
// req.headers.username, req.headers.password
// incorrect should be blocked
server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function restricted(req, res, next) {
  // realistically password does NOT belong in headers
  const { username, password } = req.headers

  if (username && password) {
    Users.findBy({username})
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        next()
      }else {
        res.status(401).json({ message: 'invalid credentials' })
      }
    })
    .catch(err => {
      res.status(500).json({ message: 'unexpected error'})
    })
  }else {
    res.status(400).json({ message: "provide username and password" })
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));

