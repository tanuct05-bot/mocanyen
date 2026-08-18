const { signToken, readJsonBody } = require('./_auth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }
  const secret = process.env.SESSION_SECRET;
  const adminPass = process.env.ADMIN_PASSWORD;
  if (!secret || !adminPass) { res.status(500).json({ error: 'Server chưa cấu hình mật khẩu quản trị' }); return; }

  const body = await readJsonBody(req);
  const password = body.password || '';
  if (password !== adminPass) { res.status(401).json({ error: 'Sai mật khẩu' }); return; }

  const token = signToken({ exp: Date.now() + 12 * 60 * 60 * 1000 }, secret);
  res.status(200).json({ token });
};
