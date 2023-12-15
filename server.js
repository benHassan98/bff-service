const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const logger = require('morgan');
const app = express();

const APP_URL = process.env.APP_URL || 'http://localhost:5173';
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:8888/oauth2/code';
const AUTH_SERVER = process.env.AUTH_SERVER || "http://localhost:8081";
const ACCOUNT_SERVICE = process.env.ACCOUNT_SERVICE || "http://localhost:8082";
const CLIENT_ID = process.env.CLIENT_ID || "oidc-client";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "4S4Hr..G0!JWOIh&";
const PORT = process.env.PORT || '8888';
const AUTH_VALUE = 'Basic ' + Buffer.from(CLIENT_ID +":"+CLIENT_SECRET).toString('base64');


app.use(cors({
    origin:APP_URL,
    credentials:true
}));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json());
app.use(cookieParser());
app.use(logger('dev'));




const getUser = async (email, headers)=>{
    let accountRes;
    try{

        accountRes = await axios.get(ACCOUNT_SERVICE+"/email/"+email,{
            headers:{
                "Content-Type":"application/json",
                "Authorization":headers['Authorization']
            },
        });

    }
    catch (e) {

        if(e.response.status === 401){
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

        return {status:err.response.status};

    }


    return {...headers, account:accountRes.data};

};
const getEmail = async (headers)=>{

    let res;

     try{
         res = await axios.get(AUTH_SERVER+'/getEmail',{
             headers:{...headers},
             withCredentials:true
         });


     }
     catch (e) {
         if(e.response.status === 401){

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
                 'refresh_token': refRes.data['refresh_token'],
                 'access_token': refRes.data['access_token'],
                 'Authorization' : `Bearer ${refRes.data['access_token']}`,
             };

             return getEmail(newHeaders);

         }

         return {
             status:e.response.status
         };

     }
    return {...headers,email:res.data};

};

app.post("/getUser", async(req,res)=>{

    const JSESSIONID = req.cookies.JSESSIONID;

    const headers = {
        'Authorization' : `Bearer ${req.body.access_token}`,
        Cookie:`JSESSIONID=${JSESSIONID};`,
        'refresh_token':req.cookies.refresh_token,
        'access_token': req.body.access_token
    };

   const {email, emailStatus, ...newHeaders} = await getEmail(headers);

    if(!email){
        res.status(emailStatus).send();
        return;
    }

   const {account, accountStatus, ...finalHeaders} = await getUser(email, newHeaders);

    if(!account){
        res.status(accountStatus).send();
        return;
    }


    res.cookie('refresh_token',finalHeaders['refresh_token'],{httpOnly:true});
    res.cookie("JSESSIONID",JSESSIONID,{httpOnly:true});

    res.send({
       account,
       access_token:finalHeaders['access_token']
   });


});



app.get("/oauth2/code",(req,res)=>{

    res.status(200).send(req.query.code);
});


app.post('/login',async (req,res)=>{

    let loginResponse, codeResponse, tokenResponse, cookieName = "JSESSIONID", cookieValue;


    try{
        loginResponse = await axios.post(AUTH_SERVER+"/perform_login",{
            email:req.body.email,
            password:req.body.password
        });

        cookieValue = loginResponse.headers["set-cookie"].find(cookie => cookie.includes(cookieName))
            ?.match(new RegExp(`^${cookieName}=(.+?);`))
            ?.[1];
    }
    catch (exception) {
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


        tokenResponse = await axios.post(AUTH_SERVER+'/oauth2/token',{
            code:codeResponse.data,
            grant_type:'authorization_code',
            redirect_uri:REDIRECT_URI
        },{
            headers: {
                'Authorization' : AUTH_VALUE,
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
    let response;

    try{
        response = await axios.post(AUTH_SERVER+'/oauth2/token',{
            client_id:CLIENT_ID,
            grant_type:'refresh_token',
            refresh_token:oldToken
        }, {
            headers: {
                'Authorization' : AUTH_VALUE,
                Cookie:`JSESSIONID=${req.cookies.JSESSIONID};`,
                "Content-Type":"application/x-www-form-urlencoded"
            },
            withCredentials:true

        });
    }
    catch (exception){
        console.log(exception);
        res.status(exception.response.status).send();
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
                "Authorization":`Bearer ${req.body.access_token}`,
                Cookie:`JSESSIONID=${req.cookies.JSESSIONID};`
            },
            withCredentials:true
        });
    }
    catch (e){
        console.log(e);
        res.status(e.response.status).send();
        return;
    }

    res.clearCookie('refresh_token',{httpOnly:true});
    res.clearCookie('JSESSIONID',{httpOnly:true});

    res.status(200).send();
});



app.listen(PORT);