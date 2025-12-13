import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookiePraser from 'cookie-parser';

//create express app 

const app =express();

//port number where app will run 

const port = process.env.port || 4000

//request will be passed in json for that we use below code
app.use(express.json());

app.use(cookiePraser());

//to send cookies in response 
app.use(cors({credentials:true}));

app.get('/', (req,res)=>res.send("API Working okay"));

app.listen(port,()=>console.log(`Server started on Port :${port}`));
