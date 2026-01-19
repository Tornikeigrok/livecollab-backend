//Import JWT and SECRET which will be used to authenticate users
//Only after the user successfully logs in, is where when you create a token, starting time that second. 
//THe token is created with you email inside, because email is what gets signed. You also pass SECRET, signing the email
// Then u create authenticateToken function, a middleware so that you ensure safety and no fake tokes will be allowed in
//first get the re.body. headers which needs to be provided by the http request in frontend. Then using that authenticate, 
//you split it, 'Bearer' is what tells backend that toke is provided, you split, only taking the token
//check if token is even provided, if not, throw error
//if it is provided, compare the token of specific user's email with SECRET, passing in (err, user)
//If token matches SECRET, that means that that user's email was signed, giving validate status
//If not, err is set to false automatically, being non-null, indicatng comparison did not pass. 
//If it passes err will be set to true. Then you set that user's email to user, req.user = user, meaning thats the email of the user
//so next time, you know that you are already verified, and then put Next(), advancing forward so that 
//without next(), you would be stuck in middleware, unable to advance forward



require('dotenv').config(); //Load environment variables

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt'); //imports cryption for password
const {Pool} = require('pg'); //library that lets JS talk to postgresSQL
const app = express();
app.use(cors());
app.use(express.json());

const jwt = require('jsonwebtoken'); //import tokens for eveytime user logs in
const SECRET = process.env.JWT_SECRET; //Use environment variable

//create http
//You need to first import raw file http, and wrap it insid eexpress, as express can only handle http requests and not websocket, and http can handle both
//create http raw server

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
})


app.post('/register', async(req, res)=>{
    const {email, password, first, last} = req.body; //incoming data and extracts email and password from it
    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
       
        if(result.rows.length > 0){
            return res.status(400).json({success: false, message: "Email is already taken"});
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await pool.query( //.query lets the DB to send data to your own database
            'INSERT INTO users (email, password, first, last) VALUES ($1, $2, $3, $4)',
            [email, hashedPassword, first, last]
        )
        res.status(201).json({success: true, message: "User Registered."});
    } catch (error) {
        res.status(500).json({success: false, message: 'Email already exists'})
    }
})

app.post('/resetpassword', async (req, res)=>{
    //get user's credentials
    //order of placeholders in table does not matter, order of this req.body does.
    const {email, last, password} = req.body;
    try {
        //get the user's info
        const userInfo = await pool.query("SELECT * FROM users WHERE email = $1",[email]);
        if(userInfo.rows.length === 0){
            return res.status(400).json({success: false, message: "No such Email exists."});
        }
         if(last !== userInfo.rows[0].last){
            return res.status(401).json({success: false, message: "No last name found in base"});
        }

        const newHashedPass = await bcrypt.hash(password, 10); //newly encrypted password
        const updatedPassword = newHashedPass;
        await pool.query("UPDATE users SET password = $1 WHERE email = $2", [updatedPassword, email]);
        res.status(200).json({success: true, message: "Password changed successfully!"});
    } catch (error) {
        res.status(500).json({success: false, message: "Client-side error/"});
    }
})

app.post('/authenticate', async(req, res)=>{
    const {email, password} = req.body; //get the user's credentials currently being passed
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if(result.rows.length === 0){ //check if users exist,  0 = -1, 1 = 1
            return res.status(400).json({success: false, message: "Invalid credentials. Try again"}); // <-- fix here
        }
        const user = result.rows[0]
        
        const match = await bcrypt.compare(password, user.password);
        if(!match){
            return res.status(401).json({success: false, message: "Invalid Credentials"});
        }
        else{
            //Secret signs token once it is created, confirming, later SECRET is used again to verify the token
            const token = jwt.sign({email: user.email}, SECRET, {expiresIn: '7h'}); //Create this token right after authentication, becaus this is when user is authorized
            res.status(200).json({success: true, message: "Successful Login", token});
        }
    } catch (error) {
        res.status(500).json({success: false, message: "Server error."});
    }
});

//critical, or else people can make fake tokens and log into your account unlawfully
function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization']; //this looks for authorization header in the incoming body request
    const token = authHeader && authHeader.split(' ')[1];
    if(!token) return res.sendStatus(401); //check if token is even provided
    jwt.verify(token, SECRET, (err, user)=>{
        if(err) return res.sendStatus(403);
        req.user = user;
        next();
    })
}

//if authentication passes, function continues to async, else it does not
app.get('/users', authenticateToken, async (req, res)=>{
    //takes the email of logged-in user.
    const email = req.user.email;
    try {
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const {first, last} = user.rows[0];
        res.status(200).json({first, last});
    } catch (error) {
        res.status(500).json({success: false, message: "Error in server side"});
    }
})



// -------------------------Documents DATABASE ----------------------------------------- -----------------------------------------

app.post('/createDocument', async (req,res)=>{
    //get user's id, first, last name, title, content, start, end times
    const { first, last, title, content } = req.body;
    try {
        const result = await pool.query("INSERT INTO documents (first, last, title, content) VALUES ($1, $2, $3, $4) RETURNING id",
            [ first, last, title, content]
        );
        const ID = result.rows[0].id;
        res.status(200).json({success:true, message: "Document created!", id: ID});
    } catch (error) {
        res.status(500).json({success: false, message: "Server-side error!", error});
    }
})

app.post('/updateDoc', async (req, res)=>{
    //get user's query
    const {content, id} = req.body;
    try {
        const getDoc = await pool.query('SELECT * FROM documents WHERE id =$1', [id]);
        if(getDoc.rows.length === 0){return res.status(404).json({success: false});}
        await pool.query("UPDATE documents SET content =$1 WHERE id =$2", [content, id]);
        res.status(200).json({success: true, message: "Successfully updated"});
    } catch (error) {
        res.status(500).json({success: false, message:"Server-side error"}, error);
    }
})

app.get('/loadContent/id', async(req, res)=>{
    const {id} = req.query;
    try {
        const getdoc = await pool.query("SELECT * FROM documents where id =$1", [id]);
         if(getdoc.rows.length === 0){return res.status(404).json({success: false,});}
         res.status(200).json({success: true, content: getdoc.rows[0].content})
    } catch (error) {
        res.status(500).json({success: false, message: "Server-side error", error})
    }
})

app.post('/updateTime', async (req, res)=>{
    const {id} = req.body;
    try {
        const getDoc = await pool.query("SELECT * FROM documents WHERE id =$1", [id]);
        if(getDoc.rows.length === 0){
            return res.status(404).json({success: false});
        }
        const result = await pool.query(
            "UPDATE documents SET updated_at = NOW() WHERE id = $1 RETURNING updated_at",
            [id]
        );
        res.status(200).json({
            success: true,
            message: "Successfully modified Date",
            updated_at: result.rows[0].updated_at
        });
    } catch (error) {
        res.status(500).json({success: false, error});
    }
});

app.post('/updateTitle', async (req,res)=>{
    const {title, id} = req.body;
    try {
        const getUser = await pool.query("SELECT * FROM documents WHERE id =$1", [id]);
         if(getUser.rows.length === 0){
            return res.status(404).json({success: false});
        }
        await pool.query('UPDATE documents SET title =$1 WHERE id=$2', [title, id]);
        res.status(200).json({success: true, message:"Successfully updated title"});
    } catch (error) {
        res.status(500).json({success: false, error});
    }
})

app.post('/deleteDocument', async (req, res)=>{
    const {id} = req.body;
    try {
        const getuser = await pool.query("DELETE FROM documents WHERE id =$1", [id]);
        res.status(200).json({success: true, message:"Deleted successfully"});
    } catch (error) {
        res.status(500).json({success:false, message: "Server-side error", error});
    }
})

app.get('/allDocuments/first/last', async (req, res)=>{
    const {first, last} = req.query;
    try {
        const result = await pool.query("SELECT * FROM documents WHERE first = $1 AND last = $2", [first, last]);
        //send all matching documnets as array/list
        res.status(200).json({success: true, documents: result.rows});
    } catch (error) {
        res.status(500).json({success: false, message: "Server-side error", error});
    }
})

//import raw file to handle both requests
const http = require('http');
const socketio = require('socket.io'); //import socketio library
const Server = socketio.Server; //then the Server class from that library
const server = http.createServer(app); //wrap app inside raw file
const io = new Server(server, {
    cors: { origin: '*'} //accessable by any localhost, unsafe but for practice
})

const socketMap = {}; //mapping for names

io.on('connection', (socket)=>{ //socket = user
    console.log('User Connected', socket.id);
    //also listen when that user disconnects
    socket.on('disconnect', ()=>{
        console.log('user disconnected', socket.id);
        //emit new list when someone leaves
     if(socket.roomId){
        socket.leave(socket.roomId);
        const users = Array.from(io.sockets.adapter.rooms.get(socket.roomId) || []);
        const names = users.map(el => socketMap[el]).filter(Boolean);
        io.to(socket.roomId).emit('updateMembers', {names});
     }
        delete socketMap[socket.id];
    })
  
   
 //check if user's typed ID exists
 //sockets are not HTTP request, so no req, res
    socket.on('userJoining', async(data)=>{
       const getdoc = await pool.query('SELECT * FROM documents WHERE id =$1', [data.id]); 
        if(getdoc.rows.length === 0){
            socket.emit('givenId', {message: "No ID exists"});
            return;
        }
        socketMap[socket.id] = {
            first: data.first,
            last: data.last
        }
        socket.emit('joinSuccess', {id: data.id});
        const roomId = String(data.id);
        socket.join(roomId);
        socket.roomId = roomId;
        socket.emit("updateContent", {content: getdoc.rows[0].content})
        //keep all users
        const users = Array.from(io.sockets.adapter.rooms.get(roomId) || []); //only holds socket IDs, u want names
        const names = users.map(el => socketMap[el]).filter(Boolean);
        io.to(roomId).emit("updateMembers", names);
        //Once user is added, add it to the DB
        //await pool.query("INSERT INTO documents (doc_id, first, last) VALUES ($1, $2, $3)", [data.id, data.first, data.last]);
    })
     socket.on('liveChanges', async (data)=>{
        const roomId = String(data.id);
        io.to(roomId).emit('tellChanges', {id: data.id, content: data.content, senderId: data.senderId})
       })
})




    app.post('/docsJoin', async(req, res)=>{
        const {doc_id, first, last} = req.body;
        try {
            const check = await pool.query("SELECT * FROM documents WHERE id =$1", [doc_id]);
            if(check.rows.length === 0){
                return res.status(404).json({success: false});
            }
            await pool.query('INSERT INTO joined_documents (doc_id, first, last) VALUES ($1,$2,$3)', [doc_id, first, last]);
            res.status(200).json({success:true, message:"Successfully added"});
        } catch (error) {
            res.status(500).json({success: false, error});
        }
    })

    app.get('/dispJoined/first/last', async(req, res)=>{
        const {first, last} = req.query;
        try {
            const check = await pool.query(
            `SELECT 
                joined_documents.doc_id, 
                joined_documents.joined_at,
                joined_documents.first AS joined_first, 
                joined_documents.last AS joined_last, 
                documents.first AS owner_first, 
                documents.last AS owner_last, 
                documents.title, 
                documents.content
             FROM joined_documents
             JOIN documents ON joined_documents.doc_id = documents.id
             WHERE joined_documents.first = $1 AND joined_documents.last = $2`,
            [first, last]
        );
            if(check.rows.length === 0){
                return res.status(200).json([]); //silence the error
            }
           res.status(200).json({
            success: true,
            doc_id: check.rows[0].doc_id,
            joined_first: check.rows[0].joined_first,
            joined_last: check.rows[0].joined_last,
            owner_first: check.rows[0].owner_first,
            owner_last: check.rows[0].owner_last,
            title: check.rows[0].title,
            content: check.rows[0].content,
            joined_at: check.rows[0].joined_at
        });
        console.log('result', check.rows[0]);
        } catch (error) {
            res.status(500).json({success: false, error});
        }
    })






const PORT = process.env.PORT || 4001;

server.listen(PORT, ()=>{
    console.log(`Server running on: http://localhost:${PORT}/`);
})


