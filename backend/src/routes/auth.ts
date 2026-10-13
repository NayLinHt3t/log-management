import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { getDummyHash, requireUser, verifyPassword, type AuthUser } from "../auth";
import { unauthorized } from "../errors";

const Login = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(1).max(200),
});

export default async function authRoutes(app: FastifyInstance) {
  const { pool, loginLimiter, metrics } = app.ctx;

  app.post("/auth/login", async (req) => {
    const { username, password } = Login.parse(req.body);
    const limiterKey = `${req.ip}|${username.toLowerCase()}`;
    loginLimiter.check(limiterKey);

    const { rows } = await pool.query(
      "SELECT id, username, password_hash, role, tenant FROM users WHERE lower(username) = lower($1)",
      [username],
    );
    const user = rows[0];
    const ok = user
      ? await verifyPassword(user.password_hash, password)
      : (await verifyPassword(await getDummyHash(), password), false);
    if (!ok) {
      loginLimiter.fail(limiterKey);
      metrics.logins.inc({ result: "failure" });
      req.log.warn({ username, ip: req.ip }, "failed login");
      throw unauthorized("invalid username or password");
    }
    loginLimiter.succeed(limiterKey);
    metrics.logins.inc({ result: "success" });
    await pool.query("UPDATE users SET last_login_at = now() WHERE id = $1", [user.id]);

    const claims: AuthUser = { uid: user.id, sub: user.username, role: user.role, tenant: user.tenant };
    const token = app.jwt.sign(claims);
    const decoded = app.jwt.decode<{ exp: number }>(token);
    return {
      token,
      expires_at: decoded?.exp ? new Date(decoded.exp * 1000).toISOString() : null,
      user: { username: user.username, role: user.role, tenant: user.tenant },
    };
  });

  app.get("/auth/me", { preHandler: requireUser }, async (req) => ({
    username: req.user.sub,
    role: req.user.role,
    tenant: req.user.tenant,
  }));
}
