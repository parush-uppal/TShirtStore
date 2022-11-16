const mongoose  = require("mongoose")
const validator = require("validator")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:[true,'Please provide a name'],
        maxlength:[40,'Name should be under 40 characters']
    },
    email:{
        type:String,
        required:[true,'Please provide a email'],
        validate:[validator.isEmail,'Please enter a valid email address'],
        unique:true
    },
    password:{
        type:String,
        required:[true,'Please provide a password'],
        minlength: [6,'Password should be atleast 6 character'],
        select:false
        
    },
    role:{
        type:String,
        default:'user'
        
    },
    photo:{
        id:{
            type:String,
            
        },
        secure_url:{
            type:String,
            
        },
        
    },
    forgotPasswordToken : String,
    forgotPasswordExpiry : Date,
    createdAt:{
        type : Date,
        default : Date.now
    }, 
});

// encrypt password before save
userSchema.pre('save',async function(next){
    if(!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password,10)
})

// validate password with passed on user password
userSchema.methods.IsvalidatedPassword = async function(usersendPassword){
   return await bcrypt.compare(usersendPassword,this.password)
};

// creating and returning jwt token
userSchema.methods.getJwtToken = function(){
    return jwt.sign({id:this.id}, process.env.JWT_SECRET,{
        expiresIn:process.env.JWT_EXPIRY,
    })
}

// generate forgot password token (string)
userSchema.methods.getForgotPasswordToken = function(){
    // generate long and random string
    const forgotToken = crypto.randomBytes(20).toString('hex')
    
    // getting a hash - make sure to get hash on backend
    this.forgotPasswordToken = crypto.createHash('sha256').update(forgotToken).digest('hex')
 
   // time of token 
   this.forgotPasswordExpiry = Date.now() + 20 * 60 
   return forgotToken
}


module.exports = mongoose.model("User",userSchema)