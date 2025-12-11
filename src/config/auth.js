const jwt = require("jsonwebtoken")


const isAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Authorization header missing or malformed" });
    }
    const token = authHeader.split(" ")[1];
    try {
        const decoded = await jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (e) {
        console.error("Error verifying token:", e);
        return res.status(401).json({ message: "Invalid or expired token" });
    }
};

module.exports = isAuth;