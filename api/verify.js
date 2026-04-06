import jwt from "jsonwebtoken";

const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

// store used proofs (basic replay protection)
const usedNonces = new Set();

export default async function handler(req, res) {
    try {
        const { proof } = req.body;

        if (!proof) {
            return res.status(400).json({ success: false, error: "No proof" });
        }

        // prevent replay attacks
        if (usedNonces.has(proof)) {
            return res.status(403).json({ success: false, error: "Replay attack" });
        }

        // 🔥 VERIFY WITH META
        const response = await fetch(
            `https://graph.oculus.com/user_nonce_validate?access_token=${META_APP_ID}|${META_APP_SECRET}&nonce=${proof}`
        );

        const data = await response.json();

        if (!data.is_valid) {
            return res.status(403).json({ success: false, error: "Meta validation failed" });
        }

        usedNonces.add(proof);

        // 🔐 CREATE JWT
        const token = jwt.sign(
            {
                user_id: data.user_id
            },
            JWT_SECRET,
            {
                expiresIn: "60s"
            }
        );

        return res.status(200).json({
            success: true,
            token
        });

    } catch (e) {
        return res.status(500).json({
            success: false,
            error: e.message
        });
    }
}
