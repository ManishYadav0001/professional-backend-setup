import express from "express";
import cookieParser from "cookie-parser";
import cors from 'cors'

const app = express();

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))


app.use(express.json({ limit: "16kb" }))

app.use(express.urlencoded({extended: true ,limit: "16kb" }))
//app.use(express.static())
app.use(cookieParser())

// userRoutes here --->

import { userRouter } from "./routes/User.routes.js";

app.use("/api/v1/users" , userRouter )


export { app }