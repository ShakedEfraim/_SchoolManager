// JWT authentication middleware
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const authenticateJWT = async (req, res, next) => {
    console.log('Authenticating');
    const token = req.signedCookies.token;
    if(!token){
        console.log('Auth failed no token');
        return res.redirect('../auth/login', {error: err.message});
    }

    try {
        const parseToken = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(parseToken);

        res.locals.user = user;
    } catch (error) {
        console.log('Auth failed token not found');
        res.redirect('../auth/login', {error: err.message});
    } finally{
        next();
    }   
};

module.exports = authenticateJWT;