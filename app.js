const express = require('express')
const { google } = require('googleapis')
const OAuth2Data = require("./credentials.json")
const multer = require("multer")
const fs = require("fs")
const { script } = require('googleapis/build/src/apis/script')
const { time } = require('console')
const Speakeasy = require("speakeasy")
const BodyParser = require("body-parser")
const { request, response } = require('express')

const bodyParser = require('body-parser');
const {JsonDB }= require('node-json-db')
const {Config}= require('node-json-db/dist/lib/JsonDBConfig')
const uuid = require("uuid");
const speakeasy = require("speakeasy")


const app = express()

//two factor authentication
app.use(express.json())
const dbConfig = new Config("myDataBase", true, false, '/')

const db = new JsonDB(dbConfig);

// app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: true }));
app.get("/api", (req,res) => {
  res.json({ message: "Welcome to the two factor authentication exmaple" })
});


//register and create temp secret 
app.post('/api/register', (req, res) => {
    const id = uuid.v4();
    try {
      const path = `/user/${id}`;
      // Create temporary secret until it it verified
      const temp_secret = speakeasy.generateSecret()
      // Create user in the database
      db.push(path, { id, temp_secret });
      // Send user id and base32 key to user
      res.json({ id, secret: temp_secret.base32})
    } catch(error) {
      console.log(error);
      res.status(500).json({ message: 'Error generating secret key'})
    }
  })
  
  app.post("/api/verify", (req,res) => {
    const { userId, token } = req.body;
    try {
      // Retrieve user from database
      const path = `/user/${userId}`;
      const user = db.getData(path);
      
      const { base32: secret } = user.temp_secret;
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token
      });
      if (verified) {
        // Update user data
        db.push(path, { id: userId, secret: user.temp_secret });
        res.json({ verified: true })
      } else {
        res.json({ verified: false})
      }
    } catch(error) {
      console.error(error);
      res.status(500).json({ message: 'Error retrieving user'})
    };
  })


// //used for two factor authentication
// app.use(BodyParser.json());
// app.use(BodyParser.urlencoded({ extended:true}));

// app.post("/totp-secret",(request, response, next) => {
//     var secret = Speakeasy.generateSecret({length:20});
//     response.send({"secret": secret.base32});
// });

// app.post("/totp-generate",(request,response,next) =>{
//     response.send({
//         "token": Speakeasy.totp({
//             secret:request.body.secret,
//             encoding:"base32"
//         }),
//         "remaining":(30 - Math.floor((new Date().getTime() / 1000.00 % 30)))
//     });
// });

// app.post("/totp-validate",(request,response,next) =>{
//     response.send({
//         "valid":Speakeasy.totp.verify({
//             secret:request.body.secret,
//             encoding:"base32",  
//             token:request.body.token,
//             window:1
//         })
//     })
// })
 

const CLIENT_ID = OAuth2Data.web.client_id
const CLIENT_SECRET = OAuth2Data.web.client_secret
const REDIRECT_URI = OAuth2Data.web.redirect_uris[0]

const oAuth2Client = new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
)

var name, photo, success
var authed = false

const SCOPES = "https://www.googleapis.com/auth/userinfo.profile"

app.set("view engine", "ejs")

app.get("/", (req, res) => {
    if (!authed) {
        var url = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES
        })

        console.log(url)
        res.render("index", { url: url })
    }
    else {
        var oauth2 = google.oauth2({
            auth: oAuth2Client,
            version: 'v2'
        })

        //user info
        oauth2.userinfo.get(function (err, response) {
            if (err) throw err

            console.log(response.data)

            name = response.data.name
            photo = response.data.picture


            res.render("success", { name: name, photo: photo, success: false })
        })
    }
})

app.get('/google/callback', (req, res) => {
    const code = req.query.code

    if (code) {

        //get an access token
        oAuth2Client.getToken(code, function (err, tokens) {
            if (err) {
                console.log("Error in Authenticaticating")
                console.log(err)
            }
            else {
                console.log("Succefully Authenticated")
                console.log(tokens)
                oAuth2Client.setCredentials(tokens)

                authed = true

                res.redirect("/")
            }
        })
    }
})

// let btnShow = document.querySelector('button')

// btnShow.addEventListener('click',()=>{
//     let today = new Date();
//     let month = today.getMonth()+1;
//     let year = today.getFullYear();
//     let date = today.getDate();

//     let current_date =`${month}/${date}/${year}`;
//     let hours = addZero(today.getHours());
//     let minutes = addZero(today.getMinutes());
//     let seconds = addZero(today.getSeconds());

//     let current_time =`${hours}:${minutes}:${seconds}`;
//     console.log(current_time);
// });

// function addZero(num){
//     return num<10?`0${num}`:num;
// }


app.get('/logout', (req, res) => {
    authed = false
    res.redirect('/')
})

app.listen(5000, () => {
    console.log("App Started on Port 5000")
})




