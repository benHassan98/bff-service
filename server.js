const express = require('express');
const axios = require('axios');
const formData = require('form-data');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const app = express();

const APP_URL = process.env.APP_URL || 'http://localhost:5173';
const AUTH_SERVER = process.env.AUTH_SERVER || "http://localhost:8080/";
const CLIENT_ID = process.env.CLIENT_ID || "oidc-client";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "secret";
const PORT = process.env.PORT || '8888';
let testVar = false;

console.log(PORT);
console.log(APP_URL);
console.log(AUTH_SERVER);
console.log(CLIENT_SECRET);
console.log(CLIENT_ID);



app.use(cors({
    origin:"*",
    credentials:true
}));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json());
app.use(cookieParser());

app.post('/login/start',async (req,res)=>{

    const form = new formData();
    form.append('username', req.body.userName);
    form.append('password', req.body.password);


    const response = await axios.post(AUTH_SERVER+'login',form);

    res.status(response.status).send();

});

app.post('/login/end',async (req,res)=>{


});


app.get('/refresh',async (req,res)=>{
    const oldToken = req.cookies.refresh_token;
    const form = new formData();
    form.append('client_id', CLIENT_ID);
    form.append('grant_type', 'refresh_token');
    form.append('refresh_token', oldToken);
    const authValue = 'Basic ' + Buffer.from(CLIENT_ID +":"+CLIENT_SECRET).toString('base64');
    const response = await axios.post(AUTH_SERVER+'oauth2/token', form, {
        headers: {
            'Authorization' : authValue,
        }
    });

    res.cookie("refresh_token",response.data.refresh_token,{
    httpOnly: true
    });
    res.send({
        access_token:response.data.access_token,
        id_token:response.data.id_token,
    });

});




app.listen(PORT);