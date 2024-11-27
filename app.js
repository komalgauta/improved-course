import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "./db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts"; // For password hashing
 
const app = new Hono();

app.use(async (c, next) => {
  try {
    // Set CSP and X-Frame-Options headers
    c.res.headers.set('X-Content-Type-Options', 'nosniff');
    c.res.headers.set("X-Frame-Options", "DENY"); // Prevent framing
    c.res.headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self';"); // Basic CSP, customize as needed

    await next();
  } catch (error) {
    console.error(error);  // Log detailed error on server side

    // Return a generic error message to the user
    return c.text("An unexpected error occurred. Please try again later.", 500);
  }
});



app.get('/login', async (c) => {
  return c.html(await Deno.readTextFile('./views/login.html'));
});

app.post('/login', async (c) => {
  const body = await c.req.parseBody();
  const email = body.email;
  const password = body.password;
  

  try {
    // Retrieve user record from the database
    const result = await client.queryObject(
      `SELECT user_id, password_hash FROM abc123_users WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      // Log failed login attempt
      await client.queryArray(
        `INSERT INTO abc123_login_logs (email, success)
         VALUES ($1, $2)`,
        [email, false]
      );
      return c.text('Invalid username or password', 401);
    }

    const storedHash = result.rows[0].password_hash;
    const userId = result.rows[0].user_id;

    // Verify the provided password with the stored hash
    const isPasswordValid = await bcrypt.compare(password, storedHash);

    if (!isPasswordValid) {
      // Log failed login attempt
      await client.queryArray(
        `INSERT INTO abc123_login_logs (user_id, success)
         VALUES ($1, $2)`,
        [userId, false]
      );
      return c.text('Invalid email or password', 401);
    }

    // Log successful login
    await client.queryArray(
      `INSERT INTO abc123_login_logs (user_id, success)
       VALUES ($1, $2)`,
      [userId, true,]
    );

    // Success response
    return c.text('Login success!');
  } catch (error) {
    console.error(error);
    return c.text('Error during login', 500);
  }
});




app.get('/', async (c) => {
  return c.html(await Deno.readTextFile('./views/index.html'));
});
 
// Serve the registration form
app.get('/register', async (c) => {
  return c.html(await Deno.readTextFile('./views/register.html'));
});
 
// Handle user registration (form submission)
app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  console.log(body);
  const username = body.username;
  const password = body.password;
  const email = body.email;
  const role = body.role;
  const age = body.age || null; // Optional
  const consent = body.consent === "on"; // Checkbox is "on" if checked

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return c.text('Invalid username', 400); // Reject invalid username
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    return c.text('Invalid email address', 400); // Reject invalid email
  }

 
  try {
    // Hash the user's password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
 
    // Insert the new user into the database
    await client.queryArray(
      `INSERT INTO abc123_users (username, password_hash, role, email, age, consent_given)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [username, hashedPassword, role, email, age, consent]
    );
 
    // Success response
    return c.text('User registered successfully!');
  } catch (error) {
    console.error(error);
    return c.text('Error during registration', 500);
  }
});
 
// Close the database connection when stopping the app
app.on("stop", async () => {
  await client.end();
});
 
// Start the application
Deno.serve(app.fetch);