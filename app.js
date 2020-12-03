const express = require('express')
const { google } = require('googleapis')
const OAuth2Data = require("./credentials.json")
const multer = require("multer")
const fs = require("fs")
const { script } = require('googleapis/build/src/apis/script')



const app = express()

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


// app.post('/upload', (req, res) => {
//     upload(req, res, function(err) {
//         if(err) {
//             console.log(err)
//         }
//         // console.log(req.file.path)
//         const drive = google.drive({
//             version: 'v3',
//             auth: oAuth2Client
//         })

//         const filemetadata = {
//             name: req.file.filename
//         }

//         const media = {
//             mimeType: req.file.mimetype,
//             body: fs.createReadStream(req.file.path)
//         }

//         drive.files.create({
//             resource: filemetadata,
//             media: media,
//             fields: "id"
//         }, (err, file) => {
//             if(err) {
//                 console.log(err)
//             }
//             console.log('SUCCESS!');
//             fs.unlinkSync(req.file.path);
//             res.render('success', {name:name, photo:photo, success:true})
//             success = true;
//             // res.redirect('/')
//         })
//     })
// })

app.get('/logout', (req, res) => {
    authed = false
    res.redirect('/')
})

app.listen(5000, () => {
    console.log("App Started on Port 5000")
})




