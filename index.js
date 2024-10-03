import dotenv from "dotenv";
import ConnecDB from "./src/db/index.js";
import { app, io } from "./app.js";
import { createServer } from 'http';

dotenv.config({
    path: './.env'
});

const server = createServer(app);
io.attach(server);

ConnecDB()
    .then(() => {
        server.listen(process.env.PORT || 4000, () => {
            console.log(`Server is running on port: ${process.env.PORT || 4000}`);
        });
    })
    .catch((err) => {
        console.log("MONGODB connection failed !! ", err);
    });