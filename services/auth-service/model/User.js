import mongoose from "mongoose"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

// User Schema 
const UserSchema = new mongoose.Schema(
    {
        name:{
            type:String,
            required:[true,"Please provide the name"],
            minLength:[3,"Name must be greater than 3 characters"],
            maxLength:[20,"Name must be less than 20 characters"]
        },
        user_name:{
            type:String,
            required:[true,"Please provide user name"],
            minLength:[3,"Name must be greater than 3 characters"],
            maxLength:[20,"Name must be less than 20 characters"],
            match: [
            /^(?!.*[_.]{2})[a-zA-Z][a-zA-Z0-9._]*[a-zA-Z0-9]$/,
            "Invalid username format",
            ],
            validate: {
                validator: function (value) {
                    const forbidden = ["admin", "root", "null", "superuser"];
                    return !forbidden.includes(value.toLowerCase());
                },
                message: "This username is not allowed",
            },
            unique:true
        },
        email:{
            type:String,
            required:true,
            match: [
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                "Please provide valid email",
              ],
            unique:true
        },
        password:{
            type:String,
            minLength:[6,"Password must be atleast 6 characters"]
        },
        status: {
            type: String,
            enum: {
              values: ["available", "offline", "away"],
              message: "Status must be either 'available', 'offline', or 'away'",
            },
            default: "offline",
        },
        profile_picture:{
            type:String
        }
    }
)

//prior to saving data into database perform following operations
UserSchema.pre("save",async function (next) {
    // generate default profile picture if not provided
    if(this.profile_picture == undefined){
        this.profile_picture = `https://ui-avatars.com/api/?background=random&name=${this.user_name}`
    }

    if(!this.isModified("password")){
        return next()
    }

    //store the hashed password into the database
    try {
        const salt = await bcrypt.genSalt(10)
        const hash_pass = await bcrypt.hash(this.password,salt)
        this.password = hash_pass
        next()
    } catch (error) {
        next(error)
    }
})

//Method to create a JWT token
UserSchema.methods.createJWT = function () {
    return jwt.sign(
      { userId: this._id },
      process.env.JWT_SECRET ?? "secret-string",
      {
        expiresIn:process.env.JWT_LIFETIME,
      },
    );
};

//Method to compare passwords
UserSchema.method.comparePassword = async function(password) {
    return await bcrypt.compare(password,this.password)
}

const User = mongoose.model("User",UserSchema)

export default User

    