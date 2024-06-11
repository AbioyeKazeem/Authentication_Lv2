import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "mypass",
  port: 5432,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    // Check if user with the provided email already exists
    const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkUser.rows.length > 0) {
      res.send("User already exists");
    } else {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      console.log("Hashed Password:", hashedPassword);

      // Insert the new user into the database with hashed password
      await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashedPassword]);
      res.render("secrets.ejs");
    }
  } catch (err) {
    console.error(err);
  }
});


app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      // Verify the password
      const passwordMatch = await bcrypt.compare(loginPassword, storedHashedPassword);
      if (passwordMatch) {
        res.render("secrets.ejs");
      } else {
        res.send("Incorrect password");
      }
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.error("Error during login:", err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
