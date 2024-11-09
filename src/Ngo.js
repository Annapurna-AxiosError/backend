import { Hono } from 'hono';

const app = new Hono();
const JWT_SECRET = "Annapurna";
const GOOGLE_CLIENT_ID = "743387480609-d2rumtr8se393tlhfau8fcnhcpt61phn.apps.googleusercontent.com";

app.use('*', async (c, next) => {
  // Add CORS headers
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  c.header('Access-Control-Max-Age', '86400');

  // Handle OPTIONS request
  if (c.req.method === 'OPTIONS') {
    return c.text('', 204);
  }

  await next();
});

// Utility: Generate JWT
async function generateJWT(payload) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(payload));

  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(data)
  );

  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${data}.${encodedSignature}`;
}

// Utility: Verify JWT
async function verifyJWT(token) {
  const [header, payload, signature] = token.split('.');
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const expectedSignature = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));

  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    expectedSignature,
    new TextEncoder().encode(data)
  );

  if (!valid) throw new Error('Invalid JWT');
  return JSON.parse(atob(payload));
}

// Middleware: JWT Authentication
async function jwtMiddleware(c, next) {
  const authHeader = c.req.raw.headers.get('authorization'); 
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const token = authHeader.slice(7); // Remove "Bearer "
  try {
    const userData = await verifyJWT(token);
    c.req.user = userData; // Attach user data (including role) to request
    await next();
  } catch (error) {
    return c.json({ error: 'Invalid token' }, 401);
  }
}

// Middleware: Admin Check
async function adminMiddleware(c, next) {
  if (!c.req.user || c.req.user.role !== 'admin') {
    return c.json({ error: 'Forbidden: Admins only' }, 403);
  }

  await next();
}

// Utility: Execute D1 Query
async function executeQuery(c, query, params = []) {
  const result = await c.env.DB.prepare(query).bind(...params).all();
  return result;
}

app.post('/auth/google', async (c) => {
  const { googleToken } = await c.req.json();

  // Verify Google token
  const googleResponse = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${googleToken}`);
  const userData = await googleResponse.json();

  // Check if the audience matches your Google Client ID
  if (userData.aud !== GOOGLE_CLIENT_ID) {
    return c.json({ error: 'Invalid Google token' }, 401);
  }

  const { name, email, picture } = userData;
  let phone = userData.phone_number || null;

  // Check if user exists in D1
  let result = await executeQuery(c, `SELECT * FROM NGOS WHERE email = ?`, [email]);
  let user;
  if (result.results.length === 0) {
    // User does not exist, create new user with default role 'customer'
    result = await executeQuery(c, `
      INSERT INTO NGOS (google_id, name, email, phone, google_pic)
      VALUES (?, ?, ?, ?, ?)
      RETURNING *;
    `, [userData.sub, name, email, phone, picture]);
    user = result.results[0];
  } else {
    user = result.results[0];
  }

  // Generate a token that includes the user's ID and role
  const ngoToken = await generateJWT({ userId: user.id, role: user.role });

  return c.json({ ngoToken, user });
});

// Route to update profile, allowing name and phone updates
app.post('/update-profile', jwtMiddleware, async (c) => {
  const { name, phone } = await c.req.json();
  const userId = c.req.user.userId;
    console.log(c.req.user);    
  const result = await executeQuery(c, `
    UPDATE NGOS
    SET name = COALESCE(?, name), phone = COALESCE(?, phone)
    WHERE id = ?
    RETURNING *;
  `, [name, phone, userId]);

  if (result.results.length === 0) {
    return c.json({ error: 'Profile update failed' }, 400);
  }

  return c.json(result.results[0]);
});

export default app;
