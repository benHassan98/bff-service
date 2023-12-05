const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const app = express();

const APP_URL = process.env.APP_URL || 'http://localhost:5173';
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:8888/oauth2/code';
const AUTH_SERVER = process.env.AUTH_SERVER || "http://localhost:8081";
const ACCOUNT_SERVICE = process.env.ACCOUNT_SERVICE || "http://localhost:8082";
const CLIENT_ID = process.env.CLIENT_ID || "oidc-client";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "4S4Hr..G0!JWOIh&";
const PORT = process.env.PORT || '8888';
const AUTH_VALUE = 'Basic ' + Buffer.from(CLIENT_ID +":"+CLIENT_SECRET).toString('base64');

console.log(PORT);
console.log(APP_URL);
console.log(AUTH_SERVER);
console.log(CLIENT_SECRET);
console.log(CLIENT_ID);



app.use(cors({
    origin:APP_URL,
    credentials:true
}));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json());
app.use(cookieParser());





const getUser = async (email, headers)=>{

    const accountRes = await axios.get(ACCOUNT_SERVICE+"/email/"+email,{
        headers:{...headers},
        withCredentials:true
    });

    if(accountRes.status === 401){
        const refRes = await axios.post(AUTH_SERVER+'/oauth2/token',{
            client_id:CLIENT_ID,
            grant_type:'refresh_token',
            refresh_token:headers['refresh_token']
        }, {
            headers: {...headers},
            withCredentials:true

        });


        const newHeaders = {
            ...headers,
            'refresh_token':refRes.data['refresh_token']
        };

        return getUser(email, newHeaders);
    }

    return {...headers, account:accountRes.data};

};
const getEmail = async (headers)=>{

    const res = await axios.get(AUTH_SERVER+'/getEmail',{
        headers:{...headers},
        withCredentials:true
    });

    console.log("email Data:  ",res.data);

    if(res.status === 401){

        const refRes = await axios.post(AUTH_SERVER+'/oauth2/token',{
            client_id:CLIENT_ID,
            grant_type:'refresh_token',
            refresh_token:headers['refresh_token']
        }, {
            headers: {...headers},
            withCredentials:true

        });

        console.log("refRes: ",refRes.data);

        const newHeaders = {
            ...headers,
            'refresh_token': refRes.data['refresh_token'],
            'access_token': refRes.data['access_token'],
            'Authorization' : `Bearer  ${refRes.data['access_token']}`,
        };

        console.log("newHeaders: ",newHeaders);


        return getEmail(newHeaders);

    }

    return {...headers,email:res.data};

};

app.post("/getUser", async(req,res)=>{

    console.log("reqBody:  ",req.body);
    const JSESSIONID = req.cookies.JSESSIONID;

    const headers = {
        'Authorization' : `Bearer  ${req.body.access_token}`,
        Cookie:`JSESSIONID=${JSESSIONID};`,
        'refresh_token':req.cookies.refresh_token,
        'access_token': req.body.access_token
    };

   const {email, ...newHeaders} = await getEmail(headers);
    console.log("email:  ",email);
    console.log("headers:   ",newHeaders);

   const {account, ...finalHeaders} = await getUser(email, newHeaders);

   console.log("account: ",account);
   console.log("finalHeaders: ",finalHeaders);

    res.cookie('refresh_token',finalHeaders['refresh_token'],{httpOnly:true});
    res.cookie("JSESSIONID",JSESSIONID,{httpOnly:true});

    res.send({
       account,
       access_token:finalHeaders['access_token']
   });


});



app.get("/oauth2/code",(req,res)=>{
    console.log(req.headers);
    console.log(req.query);
    res.status(200).send(req.query.code);
});


app.post('/login',async (req,res)=>{

    console.log(req.body.email);
    console.log(req.body.password);
    let loginResponse, codeResponse, tokenResponse, cookieName = "JSESSIONID", cookieValue;

    const authValue = 'Basic ' + Buffer.from(CLIENT_ID+":"+CLIENT_SECRET).toString('base64');


    try{
        loginResponse = await axios.post(AUTH_SERVER+"/perform_login",{
            email:'user',
            password:'password'
        });

        console.log(loginResponse.headers);
        console.log(loginResponse.data);


        cookieValue = loginResponse.headers["set-cookie"].find(cookie => cookie.includes(cookieName))
            ?.match(new RegExp(`^${cookieName}=(.+?);`))
            ?.[1];
    }
    catch (exception) {
        console.log(exception);
        console.log(exception.response.status);
        console.log(exception.response.data);

        res.status(exception.response.status).send(exception.response.data);
        return;
    }

    try{

        codeResponse = await axios.get(AUTH_SERVER+`/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid`
            ,{
                headers:{
                    Cookie:`${cookieName}=${cookieValue};`
                },
                withCredentials:true
            });
        console.log("codeResponse: ",codeResponse.data);

        tokenResponse = await axios.post(AUTH_SERVER+'/oauth2/token',{
            code:codeResponse.data,
            grant_type:'authorization_code',
            redirect_uri:REDIRECT_URI
        },{
            headers: {
                'Authorization' : authValue,
                Cookie:`JSESSIONID=${cookieValue};`,
                "Content-Type":"application/x-www-form-urlencoded"
            },
            withCredentials:true
        });


    }
    catch (exception){
        res.status(500).send();
        return;
    }




    console.log("codeResponse:   ",codeResponse.status);
    console.log("codeResponse:   ",codeResponse.data);


    const access_token = tokenResponse.data.access_token;
    const refresh_token = tokenResponse.data.refresh_token;

    res.cookie('refresh_token',refresh_token,{httpOnly:true});
    res.cookie(cookieName,cookieValue,{httpOnly:true});
    res.send({
        access_token
    });


});

app.get('/refresh',async (req,res)=>{
    const oldToken = req.cookies.refresh_token;
    const authValue = 'Basic ' + Buffer.from(CLIENT_ID +":"+CLIENT_SECRET).toString('base64');
    let response;

    try{
        response = await axios.post(AUTH_SERVER+'/oauth2/token',{
            client_id:CLIENT_ID,
            grant_type:'refresh_token',
            refresh_token:oldToken
        }, {
            headers: {
                'Authorization' : authValue,
                Cookie:`JSESSIONID=${req.cookies.JSESSIONID};`,
                "Content-Type":"application/x-www-form-urlencoded"
            },
            withCredentials:true

        });
    }
    catch (exception){
        console.log(exception);
        res.status(500).send();
        return;
    }

    res.cookie("refresh_token",response.data.refresh_token,{
    httpOnly: true
    });
    res.send({
        access_token:response.data.access_token,
        id_token:response.data.id_token,
    });

});

app.post('/logout',async (req,res)=>{

    try{
        await axios.get(AUTH_SERVER+'/perform_logout',{
            headers: {
                Cookie:`JSESSIONID=${req.cookies.JSESSIONID};`
            },
            withCredentials:true
        });
    }
    catch (exception){
        console.log(exception);
        res.status(500).send();
        return;
    }

    res.clearCookie('refresh_token',{httpOnly:true});
    res.clearCookie('JSESSIONID',{httpOnly:true});

    res.status(200).send();
});

app.get("/err",(req,res)=>{
    res.status(404).send();
});



app.listen(PORT);