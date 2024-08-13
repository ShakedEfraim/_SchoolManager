
const router = require('express').Router();
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Register
router.get('/register', (req, res) => {
    res.renderWithLayout('auth/register');
});

router.post('/register', async (req, res) => {

    try {
        const { username, password, name } = req.body;

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            username,
            password: hashedPassword,
            name
        });
    
        // 3. Save the user
        await user.save();

        // 4. Redirect to 'login'
        res.redirect('login');
    } catch (error) {
        console.log(`Error: ${error.message}`);
        res.renderWithLayout('/register', {error: error.message});
    }
});

// Login
router.get('/login', async (req, res) => {
    res.renderWithLayout('auth/login');
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.renderWithLayout('auth/login', { error: 'Username is not found' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.renderWithLayout('auth/login', { error: 'Invalid password' });

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {expiresIn: '15m'});
    res.
        cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', signed: true }).
        redirect('../accounts/dashboard');
});

router.post('/logout', (req, res) => {
    res.clearCookie('token').redirect('../auth/login');
});

module.exports = router;
