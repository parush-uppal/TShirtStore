const User = require("../models/user")
const BigPromise = require("../middleware/bigPromise")
const cookieToken = require("../utils/cookieToken")
const fileUpload = require("express-fileupload")
const cloudinary = require("cloudinary")

exports.signup = BigPromise(async (req,res,next) =>{

    let result;
    if(req.files){
        let file =req.files.photo
        result = await cloudinary.v2.uploader.upload(file.tempFilePath,{
            folder:"user",
            width:150,
            crop:"scale"
        })

    }


    const {name,email,password} = req.body

    if(!email || !name || !password){
        return next(new Error("All feild are required"))

    }
    const user = await User.create({
        name,
        email,
        password,
        photo:{
            id:result.public_id,
            secure_url: result.secure_url
        }
    })
    cookieToken(user,res);
})