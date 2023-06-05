/*
Author: Nikolas Manuel
Description: create a simple to-do calender program with a login and password using promises and SQLite Database, we will “salt” a password and set up an 
Authentication Token.  
*/
const sqlite3 = require('sqlite3');
const sqlite = require('sqlite');
const express = require('express');
const bcrypt = require('bcrypt');
const {v4: uuidv4} = require('uuid');
const app = express();
const handlebars = require('express-handlebars');
const cookieParser = require('cookie-parser');
const saltRounds = 10;
const path = require('path');

const port = 8080;

app.engine("handlebars", handlebars.engine());
app.set("view engine","handlebars");

app.use(express.static("static"));
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));

// opens up to-do list database
const dbPromise = sqlite.open({
    filename: './database/todolist.sqlite',
    driver: sqlite3.Database,
});

// get the authtoken when user lands on the page 
const authMiddleware = async (req,res,next)=> {
    console.log(req.cookies);
    if(!req.cookies || !req.cookies.authtokens)
    {
        return next();
    }
    const db = await dbPromise;
    const authtokens = await db.get(`SELECT * FROM authtokens WHERE token = ?`, req.cookies.authToken);
    if(!authtokens)
    {
        return next();
    }
    const user = await db.get(`SELECT user_id, username FROM users where user_id = ?`,authtokens.user_id);
    req.user = user;
    next();
};

app.use(authMiddleware);


// listens to the port
app.listen(port,() =>{
    console.log(`Server started on port: ${port}`);
});

// gets logout and clears the authtoken and redirects them back to the login page
app.get("/logout",(req,res) =>{
    res.clearCookie("authToken");
    res.redirect("/login");
})
//renders the home page
app.get("/", async (req,res) => {
    const db = await dbPromise;
    let id = req.cookies.id 
    
    let allTasks = await db.all('SELECT*FROM tasks WHERE user_id = ?', id)

    res.render("home",{layout: 'main', 'tasks': allTasks});
});

  
// renders the register page
app.get("/register",(req,res) =>{
    res.render("register");
});
// renders the log in page
app.get("/login",(req,res) =>{
    res.render("login");
});
// let user create a account
app.post("/register", async (req,res) =>{
    const {
        username,
        password,
        confirmPassword
    } = req.body;
    if (!username || !password || !confirmPassword)
    {
        return res.render("register", { error: "all fields are required" });
    }
    if (password !== confirmPassword) 
    {
        return res.render("register", { error: "passwords must match" });
    }
    
    const db = await dbPromise;
    // once user creates an account it will hash the password
    try{
        const passwordHash = await bcrypt.hash(password,saltRounds); // creates hash password
        console.log("passwordHash : ", passwordHash);
        await db.run(`INSERT INTO users(username,password) VALUES (?,?)`, username,passwordHash); // inserts it to the database

        const createdUser = await db.get(`SELECT * FROM users WHERE username = ?`,username); // gets the username 

        const token = uuidv4();
        await db.run(`INSERT INTO authtokens(token,user_id) VALUES(?,?)`,token,createdUser); // creates authtoken for the user
        res.cookie('authToken', token); // keeps the auth token as a cookie
        res.cookie('id', createdUser.user_id);
    }
    catch(e)
    {
        console.log(e);
        return res.render('register', {error: 'something went wrong'}); // error message 
        
    }
    res.redirect('/'); // redirects them to the home page
});
app.post('/login', async(req,res)=>{
    const {username, password} = req.body;
    const db = await dbPromise;
    if(!username || !password)
    {
        return res.render("login",{error: "all fields are required"});
    }

    try{
        const user = await db.get(`SELECT * FROM users WHERE username = ?`, username); // gets the user name
        if(!user)
        {
            return res.render('login',{error:'username or password incorrect'}); // if its not the user it will send an error message
        }

        const passwordMatches = await bcrypt.compare(password, user.password); // compares the password and confirm password to make sure they are the same
        if(!passwordMatches)
        {
            return res.render('login',{error:'username or password incorrect'}); // error message
        }
        const token = uuidv4();

        await db.run(`INSERT INTO authtokens(token,user_id) VALUES(?,?)`,token,user.user_id); // creates authtoken
        res.cookie('authToken', token); // stores the auth token to a cookie
    }
        
    catch(e)
    {
        console.log(e);
        return res.render('login', {error: 'something went wrong'}); // error message
    }
    
    res.redirect('/');
});

app.post("/add_task", async(req,res) =>{
    const db = await dbPromise;
    const newTask = req.body.tasks;
    let id = req.cookies.id 
    try {
        let insertTask = await db.run(`INSERT INTO tasks (user_id, task_desc, is_complete) VALUES (?,?,?)`, id, newTask, 0);
        console.log('Task inserted successfully');
      } catch (error) {
        console.error('Error inserting task:', error);
      }
      
    res.redirect('/');
});

// Handle the submission of completed tasks
// Handle the submission of completed tasks
app.post("/complete_task", async (req, res) => {
    const db = await dbPromise;
    const taskId = req.body.task_id; // Get the task ID from the submitted form
    let id = req.cookies.id;
  
    // Update the task's completion status in the database
    await db.run(
      `UPDATE tasks SET is_complete = ? WHERE user_id = ? AND task_id = ?`,
      1,
      id,
      taskId
    );
  
    res.redirect("/");
  });
  

// Handle the removal of completed tasks
app.post("/remove_completed_tasks", async (req, res) => {
    const db = await dbPromise;
    const id = req.cookies.id;

    // Remove all completed tasks for the user
    await db.run(`DELETE FROM tasks WHERE user_id = ? AND is_complete = ?`, id, 1);

    res.redirect("/");
});

