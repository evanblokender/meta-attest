import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;

export default async function handler(req, res) {
    try {
        const token = req.query.token;

        if (!token) {
            return res.status(400).send("Missing token");
        }

        const decoded = jwt.verify(token, JWT_SECRET);

        return res.status(200).json({
            ResultCode: 1,
            UserId: decoded.user_id
        });

    } catch (e) {
        return res.status(403).send("Invalid token");
    }
}
