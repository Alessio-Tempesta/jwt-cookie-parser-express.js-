import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import * as bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cookieParser());

const chiaveSegreta = 'PasswordUltraMegaSegreta123';

// Verifica Token JWT

const verificaToken = ( req, res, next ) => {
    const token = req.cookies.token;
    if (!token ) return res.status(401).send("token non trovato");

    jwt.verify(token, chiaveSegreta, (err, decoded) => {
        if(err) return res.status(403).send("token non valido");
        req.user = decoded;
        next();
    })
};

// Rotta Login 
app.post('login', async (req, res )=> {
    const { username, password} = req.body;
    const user = await prisma.user.findUnique( { where : { username }});
    if(!user) return res.status(404).send("Utente non trovato");

    const passwordValida = await bcrypt.compare(password, user.password);
    if (!passwordValida) return res.status(401).send("password invalida o non corretta");

    const token  = jwt.sign({ userId: user.id} , chiaveSegreta);
    res.cookie("cookie" , token, { httpOnly: true});
    res.send("Login effetuato con successo");
});

// Rotta del profilo 
app.get('/profile', verificaToken, async ( req , res) => {
    const { userId } = req.user;
    const user = await prisma.user.findUnique( { where : { id: userId }});
    res.json(user);
})

// Rotta logout 
app.post('logout', (req, res) => {
    req.session.destroy()
    res.clearCookie("Cookie");
    res.send("Logout effettuato con successo")
});

app.listen( 80 , () => {
    console.log("Il server è in funzione alla porta 80");
});