const User = require("../models/user")
const BigPromise = require("../middleware/bigPromise")
const cookieToken = require("../utils/cookieToken")
const fileUpload = require("express-fileupload")
const cloudinary = require("cloudinary")
const mailHelper = require("../utils/emailHelper")
const crypto = require("crypto")

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

exports.login = BigPromise(async (req,res,next) =>{
     const {email,password} = req.body

     // Check for presence of email and password
     if(!email || !password){
        return next(new Error("Please provide email and password"))
     }

     const user = await User.findOne({email}).select("+password")

     if(!user){
        return next(new Error("You are not please rergister first"))
     }

     const isPasswordCorrect = await user.isValidatedPassword(password)

     if(!isPasswordCorrect){
        return next(new Error("Please enter correct password"))
     }
     cookieToken(user,res)
})

exports.logout = BigPromise(async (req,res,next) =>{
    
    res.cookie('token',null,{
        expires: new Date(Date.now()),
        httpOnly: true
    })

    res.status(200).json({
        success:true,
        message:"Logout Success"
    })
    
})

exports.forgotPassword = BigPromise(async (req,res,next) =>{
    
    const {email} = req.body

    const user = await User.findOne({email})

    if(!user){
        return next(new Error('Email not found',500))
    }

    const forgotToken = user.getForgotPasswordToken()

    await user.save({validateBeforeSave:false})

    const myUrl = `${req.protocol}://${req.get("host")}/password/reset/${forgotToken}`

    const message = `Copy paste this link to reset password \n\n ${myUrl}`

    try {
        await mailHelper({
            email:user.email,
            subject:"TShirt Store password reset email",
            message
        })
        res.status(200).json({
            success:true,
            message:"Password reset email sent successfull"
        })
    } catch (error) {
        user.forgotPasswordToken = undefined
        user.forgotPasswordExpiry = undefined
        await user.save({validateBeforeSave:false})
        return next(new Error(error.message,500))
    }
    
    
})

exports.passwordReset = BigPromise(async (req,res,next) =>{
    
    const token  = req.params.token

    const encryToken = crypto.createHash('sha256').update(token).digest('hex')

    const user = await User.findOne({
        encryToken,
        forgotPasswordExpiry: {$gt: Date.now()}
    })

    if(!user){
        return next(new Error("Token is invalid or expired"))
    }
    
    if(req.body.password != req.body.confirmPassword){
        return next(new Error("Password and confirm password does not match",400))
    }
    user.password = req.body.password
    user.forgotPasswordToken = undefined
    user.forgotPasswordExpiry = undefined

    await user.save()
    
    // send a json response or send a cookie
    cookieToken(user,res)
})

exports.getLoggedInUserDetails = BigPromise(async (req,res,next) =>{
       const user = await User.findById(req.user.id);

       res.status(200).json({
        success:true,
        user
       })
})

exports.changePassword = BigPromise(async (req,res,next) =>{
    const userId = req.user.id

    const user = await User.findById(userId).select("+password");

   const isCorrectOldPassword = await user.isValidatedPassword(req.body.oldPassword)

   if(!isCorrectOldPassword){
    return next(new Error("Old password is incorrect",400))
   }

   user.password = req.body.password

   await user.save()

   cookieToken(user,res)
})

exports.updateUserDetails = BigPromise(async (req, res, next) => {
    // add a check for email and name in body
  
    // collect data from body
    const newData = {
      name: req.body.name,
      email: req.body.email,
    };
  
    // if photo comes to us
    if (req.files) {
      const user = await User.findById(req.user.id);
  
      const imageId = user.photo.id;
  
      // delete photo on cloudinary
      const resp = await cloudinary.v2.uploader.destroy(imageId);
  
      // upload the new photo
      const result = await cloudinary.v2.uploader.upload(
        req.files.photo.tempFilePath,
        {
          folder: "users",
          width: 150,
          crop: "scale",
        }
      );
  
      // add photo data in newData object
      newData.photo = {
        id: result.public_id,
        secure_url: result.secure_url,
      };
    }
  
    // update the data in user
    const user = await User.findByIdAndUpdate(req.user.id, newData, {
      new: true,
      runValidators: true,
      useFindAndModify: false,
    });
  
    res.status(200).json({
      success: true,
    });
});

exports.adminAllUser = BigPromise(async (req, res, next) => {
    // select all users
    const users = await User.find();
  
    // send all users
    res.status(200).json({
      success: true,
      users,
    });
});

exports.admingetOneUser = BigPromise(async (req, res, next) => {
    // get id from url and get user from database
    const user = await User.findById(req.params.id);
  
    if (!user) {
      next(new Error("No user found", 400));
    }
  
    // send user
    res.status(200).json({
      success: true,
      user,
    });
});
  
exports.adminUpdateOneUserDetails = BigPromise(async (req, res, next) => {
    // add a check for email and name in body
  
    // get data from request body
    const newData = {
      name: req.body.name,
      email: req.body.email,
      role: req.body.role,
    };
  
    // update the user in database
    const user = await User.findByIdAndUpdate(req.params.id, newData, {
      new: true,
      runValidators: true,
      useFindAndModify: false,
    });
  
    res.status(200).json({
      success: true,
    });
});
  
exports.adminDeleteOneUser = BigPromise(async (req, res, next) => {
    // get user from url
    const user = await User.findById(req.params.id);
  
    if (!user) {
      return next(new Error("No Such user found", 401));
    }
  
    // get image id from user in database
    const imageId = user.photo.id;
  
    // delete image from cloudinary
    await cloudinary.v2.uploader.destroy(imageId);
  
    // remove user from databse
    await user.remove();
  
    res.status(200).json({
      success: true,
    });
});
  
exports.managerAllUser = BigPromise(async (req, res, next) => {
    // select the user with role of user
    const users = await User.find({ role: "user" });
  
    res.status(200).json({
      success: true,
      users,
    });
});
  
  