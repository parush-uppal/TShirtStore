const express = require("express")
require("dotenv").config();
const app = express()
const morgan = require("morgan");
const cookieParser = require("cookie-parser")
const fileUpload = require("express-fileupload")


// regular middleware
app.use(express.json())
app.use(express.urlencoded({extended:true}))

// cookies and file middleware
app.use(cookieParser());
app.use(fileUpload({
    useTempFiles:true,
    tempFileDir:"/tmp/",
}));


//morgan middleware
app.use(morgan("tiny"));

// import all routes here
const home = require("./routes/home")
const user = require("./routes/user")

//route middleware
app.use("/api/v1", home);
app.use("/api/v1", user);


// export app js
module.exports = app;