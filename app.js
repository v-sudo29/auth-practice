// DO NOT UPLOAD TO GITHUB
require('dotenv').config()
const bcrypt = require('bcryptjs')
const express = require('express')
const path = require('path')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local')
const mongoose = require('mongoose')
const { nextTick } = require('process')
const Schema = mongoose.Schema

const mongoDb = process.env.MONGO_DB_URI
mongoose.connect(mongoDb, { 
  useUnifiedTopology: true, 
  useNewUrlParser: true 
})

const db = mongoose.connection
db.on('error', console.error.bind(console, 'mongo connection error'))

const User = mongoose.model('User', new Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
  })
)

const app = express()
app.set('views', __dirname)
app.set('view engine', 'ejs')

// Setting up the LocalStrategy
passport.use(new LocalStrategy(async(username, password, done) => {
  try {
    const user = await User.findOne({ username: username })
    const match = bcrypt.compare(password, user.password)
    if (!user) {
      return done(null, false, { message: 'Incorrect username' })
    }
    if (!match) {
      return done(null, false, { message: 'Incorrect password' })
    }
    return done(null, user)
  } catch(err) {
    return done(err)
  }
}))

// Setting up sessions and serialization
passport.serializeUser(function(user, done) {
  done(null, user.id)
})

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id)
    done(null, user)
  } catch(err) {
    return done(err)
  }
})

app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))
app.use(function(req, res, next) {
  res.locals.currentUser = req.user
  next()
})

app.get('/', (req, res) => {
  res.render('index', { user: req.user })
})
app.get('/log-out', (req, res, next) => {
  req.logout(function(err) {
    if (err) return next(err)
    res.redirect('/')
  })
})
app.get('/sign-up', (req, res) => res.render('sign-up-form'))
app.post('/sign-up', async (req, res) => {
  bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
    if (err) next(err)
    else {
      const user = new User({
        username: req.body.username,
        password: hashedPassword
      })
      const result = await user.save()
      res.redirect('/')
    }
  })
})

app.post('/log-in', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/'
}))

app.listen(3000, () => console.log('app listening on port 3000'))