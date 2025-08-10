import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiErrors.js";
import { User } from "../models/user.model.js";
import { uploadCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/apiResponse.js";

const registerUser = asyncHandler(



    async (req, res) => {

       

       

        // step-1 - getting data from the frontend (json data not avatar or coverImage)

        const { username, email, fullName, password } = req.body


        // step-2- checking if any of the field is empty 

        if (username === "") {
            throw new ApiError(400, "username is empty")
        }

        if (email === "") {
            throw new ApiError(400, "email is empty")
        }

        if (fullName === "") {
            throw new ApiError(400, "fullName is empty")
        }

        if (password === "") {
            throw new ApiError(400, "password is empty")
        }


        //step-3-  checking if user already registered in the database or not

        const existedUser = await User.findOne({
            $or: [{ username }, { email }]
        });

        if (existedUser) {
            throw new ApiError(409, "user already exists")
        }



        // step-4- check for image and check for avatar --

        const avatarLocalPath = req.files?.avatar[0]?.path;
        // const coverimageLocalPath = req.files?.coverimage[0]?.path;

        let coverimageLocalPath;
        if (req.files && Array.isArray(req.files.coverimage) && req.files.coverimage.length > 0) {

            coverimageLocalPath = req.files?.coverimage?.[0]?.path;
        }


        if (!avatarLocalPath) {
            throw new ApiError(400, "avatar not found")
        }

        //step-5- upload avatar and coverImage on cloudinary --


        const Avatar = await uploadCloudinary(avatarLocalPath)

        const Coverimage = await uploadCloudinary(coverimageLocalPath)

        if (!Avatar) {
            throw new ApiError(500, "can't upload avatar")
        }

        //step-6- create entry in db --

        const user = await User.create({
            fullName,
            password,
            email,
            username: username.toLowerCase(),
            coverimage: Coverimage.url || "",
            avatar: Avatar.url,

        })


        // step-7- remove password and referesh token field from the data -- 

        const createdUser = await User.findById(user._id).select(
            "-password -refereshToken"
        )

        // step-8- checking for user creation -- 
        if (!createdUser) {
            throw new ApiError(500, " Something went wrong while registering the user")

        }

        //step-9- returning response --- 

        return res.status(201).json(

            new ApiResponse(201, createdUser, "user Registered Succesfully")

        )

    }
)

export { registerUser }