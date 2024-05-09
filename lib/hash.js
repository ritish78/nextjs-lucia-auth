import crypto from "node:crypto";

export function hashPassword(passwordInPlainText) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hashedPassword = crypto.scryptSync(passwordInPlainText, salt, 64);

  return hashedPassword.toString("hex") + ":" + salt;
}

export function verifyPassword(passwordInPlainText, hashedPasswordFromDB) {
  const [hashedPassword, salt] = hashedPasswordFromDB.split(":");
  const hashedPasswordBuf = Buffer.from(hashedPassword, "hex");
  const plainTextPasswordBuf = crypto.scryptSync(passwordInPlainText, salt, 64);
  return crypto.timingSafeEqual(plainTextPasswordBuf, hashedPasswordBuf);
}
