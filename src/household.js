import { Hono } from 'hono'

const app = new Hono()
const JWT_SECRET="Annapurna";
const GOOGLE_CLIENT_ID="743387480609-d2rumtr8se393tlhfau8fcnhcpt61phn.apps.googleusercontent.com";

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
  console.log(userData);
  // Check if the audience matches your Google Client ID
  if (userData.aud !== GOOGLE_CLIENT_ID) {
    return c.json({ error: 'Invalid Google token' }, 401);
  }

  const { name, email, picture } = userData;

  // Attempt to fetch the user's phone number
  let phone = null;
  if (userData.phone_number) {
    phone = userData.phone_number; // If the phone number is available in the userData
  }
  
  // Check if user exists in D1
  let result = await executeQuery(c, `SELECT * FROM users WHERE email = ?`, [email]);
  let user;
  if (result.results.length === 0) {
    // Check if username already exists
    let usernameCheck = await executeQuery(c, `SELECT * FROM users WHERE username = ?`, [name]);
    let finalUsername = name;
    if (usernameCheck.results.length > 0) {
      finalUsername = email; // Use email as username if the username already exists
    }

    // User does not exist, create new user with default role 'customer'
    result = await executeQuery(c, `
      INSERT INTO users (google_id, username, email, phone, google_pic)
      VALUES (?, ?, ?, ?, ?)
      RETURNING *;
    `, [userData.sub, finalUsername, email, phone, picture]);
    user = result.results[0];
  } else {
    user = result.results[0];
  }
  
  // Generate a token that includes the user's ID and role
  const token = await generateJWT({ userId: user.user_id, role: user.role });

  return c.json({ token, user });
});

//get user
app.get('/user', jwtMiddleware, async (c) => {
  const { userId } = c.req.user;
  const result = await executeQuery(c, `SELECT * FROM users WHERE user_id = ?`,
    [userId]);
  return c.json(result.results[0]);
  });



//endpoint to create a family
app.post('/family', jwtMiddleware, async (c) => {
  const userId = c.req.user.userId;
  //generate a random 4 digit family code
  const family_code = Math.floor(1000 + Math.random() * 9000);
  console.log(family_code);
  const { family_name } = await c.req.json();
  const result = await executeQuery(c, `
    INSERT INTO Families (family_name, family_code, created_by)
    VALUES (?, ?,?)
    RETURNING *;
  `, [family_name, family_code ,userId]);
  //update user profile with family_id
  const family_id = result.results[0].family_id;
  const result2 = await executeQuery(c, `
    UPDATE users 
    SET current_family_id = ? 
    WHERE user_id = ?
    RETURNING *;
`, [family_id, userId]);
    return c.json({ family_id, family_code });
});


//ENDPOINT TO JOIN A FAMILY
app.post('/joinfamily', jwtMiddleware, async (c) => {
  const userId = c.req.user.userId;
  const { family_id } = await c.req.json();

  const result = await executeQuery(c, `
    SELECT * FROM Families WHERE family_id = ?;
    `, [family_id]);
    if (result.results.length === 0) {
      return c.status(404).json({ message: 'Family not found' });
    }
    return result;
  });

//endpoint to update user profile phone and family_id
app.post('/update-profile', jwtMiddleware, async (c) => {
  const userId = c.req.user.userId;
  const { phone, family_id } = await c.req.json();
  const result = await executeQuery(c, `
    UPDATE users 
    SET phone = ?, current_family_id = ? 
    WHERE user_id = ?
    RETURNING *;
  `, [phone, family_id, userId]);
  return c.json(result.results[0]);
});


//endpoint to add product with userid 
app.post('/product', jwtMiddleware, async (c) => {
  //add user_id from the token
  const userId = c.req.user.userId;
  

  const { name,expiry_date, quantity, category,notes} = await c.req.json();
  if(category === undefined || category === null){ 
      return c.json({ error: 'Category is required' }, 400);
    }
//check if category is valid 'Dairy', 'Vegetables', 'Fruits', 'Grains', 'Meat', 'Packaged', 'Other', 'cooked'
  if(category !== 'Dairy' && category !== 'Vegetables' && category !== 'Fruits' && category !== 'Grains' && category !== 'Meat' && category !== 'Packaged' && category !== 'Other' && category !== 'cooked'){
    return c.json({ error: 'Invalid Category' }, 400);
  }

  const result = await executeQuery(c, `
    INSERT INTO Food_Items (food_name,expiry_date, quantity, category,notes , user_id)
    VALUES (?, ?, ?, ?, ?, ?)
    RETURNING *;
  `, [name,expiry_date, quantity, category,notes,userId]);
  return c.json(result.results[0]);
});

//get all products of user along with the user's data and family members' products
app.get('/products', jwtMiddleware, async (c) => {
  const userId = c.req.user.userId;
  
  // Query to fetch the user's products along with user details
  const result = await executeQuery(c, `
    SELECT 
      Food_Items.*, 
      users.username, 
      users.email, 
      users.phone, 
      users.google_pic 
    FROM 
      Food_Items
    JOIN 
      users ON Food_Items.user_id = users.user_id
    WHERE 
      Food_Items.user_id = ?;
  `, [userId]);

  return c.json(result.results);
});


//all products no user id with user data
app.get('/all-product', jwtMiddleware, async (c) => {
  const userId = c.req.user.userId;
  const result = await executeQuery(c, `
    SELECT 
      Food_Items.*, 
      users.username, 
      users.email, 
      users.phone, 
      users.google_pic,
      users.current_family_id 
    FROM 
      Food_Items
    JOIN 
      users ON Food_Items.user_id = users.user_id;
  `, []);
  
  return c.json(result.results);
});



//a open endpoint to add product by finding the user by phone
app.post('/add-product', jwtMiddleware, async (c) => {
  const { name, price, quantity, userPhone } = c.req.body;
  function findUserByPhone(c, phone) {
    return executeQuery(c, `SELECT user_id FROM users WHERE phone = ?`, [phone]);
  }
  const user = await findUserByPhone(c, userPhone);
  const userId = user.results[0].user_id;
  if (!userId) {
    return c.status(404).json({ message: 'User not found' });
    }
    const result = await executeQuery(c, `
      INSERT INTO Food_Items (name, price, quantity, user_id)
      VALUES (?, ?, ?, ?);
      `, [name, price, quantity, userId]);
      return c.json(result);
      });
      
    
export default app
