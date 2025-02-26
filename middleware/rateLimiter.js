const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
    windowMS: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { error: "Too many Requests from this IP, Please Try-Again"},
    headers: true, // Send rate limit headers
});

module.exports = apiLimiter;
