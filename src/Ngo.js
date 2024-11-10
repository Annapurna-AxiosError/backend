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

// Route to update phone, allowing name and phone updates
app.post('/update-phone', jwtMiddleware, async (c) => {
  const { phone } = await c.req.json();
  const userId = c.req.user.userId;
    console.log(c.req.user.userId);    
    const result = await executeQuery(c, `
        UPDATE NGOS
        SET  phone = ?
        WHERE id = ?
        `, [ phone, userId]);
        return c.json({ result: 'Phone Number updated successfully' });
});

//route to update ngo name
app.post('/update-name', jwtMiddleware, async (c) => {
    const { name } = await c.req.json();
    const userId = c.req.user.userId;
    const result = await executeQuery(c, `
        UPDATE NGOS
        SET  name = ?
        WHERE id = ?
        `, [ name, userId]);
        return c.json({ result: 'Name updated successfully' });
});

//NGO create campaign
//create a notification in Notifications table
// name notification_date message is_read-false created_at-timestamp 
app.post('/campaign', jwtMiddleware, async (c) => {
    const { campaign_title, campaign_description, food_type, food_category, availability_start_time,availability_end_time,pickup_location,latitude,longitude,pickup_type } = await c.req.json();
    const userId = c.req.user.userId;
    
    //check if food category is 'Vegetarian', 'Non-Vegetarian', 'Vegan'
    if (food_category !== 'Vegetarian' && food_category !== 'Non-Vegetarian' && food_category !== 'Vegan') {
        return c.json({ error: 'Invalid food category' }, 400);
    }

    //check if food type is 'Cooked', 'Raw', 'Packaged'
    if(food_type !== 'Cooked' && food_type !== 'Raw' && food_type !== 'Packaged'){
        return c.json({ error: 'Invalid food type' }, 400);
    }

    //check if pickup type is 'Self-Drop'or 'Volunteer Pickup'
    if(pickup_type !== 'Self-Drop' && pickup_type !== 'Volunteer Pickup'){
        return c.json({ error: 'Invalid pickup type' }, 400);
    }

    // Insert campaign into CAMPAIGN table
    const campaignResult = await executeQuery(c, `
        INSERT INTO CAMPAIGN (ngo_id, campaign_title, campaign_description, food_type, food_category, availability_start_time,availability_end_time,pickup_location,latitude,longitude,pickup_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *;
    `, [userId, campaign_title, campaign_description, food_type, food_category, availability_start_time,availability_end_time,pickup_location,latitude,longitude,pickup_type]);
      console.log(campaignResult);
    // Create notification
    const notificationMessage = `New campaign created: ${campaign_title}`;
    await executeQuery(c, `
        INSERT INTO Notifications (name, notification_date, message, is_read, created_at)
        VALUES (?, ?, ?, ?, ?);
    `, [campaign_title, new Date().toISOString(), notificationMessage, false, new Date().toISOString()]);

    return c.json({ result: 'Campaign created successfully' });
});

//get campaigns public endpoint
app.get('/campaigns', async (c) => {
    //merge ngo details along with the campaign details
    const result = await executeQuery(c, `
        SELECT * FROM CAMPAIGN
        JOIN NGOS ON CAMPAIGN.ngo_id = NGOS.id;
        `);
        return c.json(result);
        
});

//whatsapp api webhook
app.get("/webhook", async (c) => {
    //get token from arguments
    
    });

  //get notofications of user
  app.get('/notifications', async (c) => {
    const result = await executeQuery(c, `
      SELECT * FROM Notifications
      WHERE is_read = false;
    `);
    return c.json(result);
  }
);

export default app;
