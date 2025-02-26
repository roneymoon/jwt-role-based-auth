const roleMiddleware = (roles) => {
    return (req, res, next) => {
        if(!roles.includes(req.user.role)){
            res.status(403).json({message: "Forbidden: Insufficient Permissions"});
        }
        next();
    };
}

module.exports = roleMiddleware;