import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiErrors.js";
import { User } from "../models/user.model.js";
import { uploadCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefereshToken = async (userId) => {

    try {

        const user = await User.findById(userId)

        const AccessToken = user.generateAccessToken()
        const RefereshToken = user.generateRefreshToken()

        user.refreshToken = RefereshToken
        await user.save({ validateBeforeSave: false })

        return { AccessToken, RefereshToken }


    } catch (error) {
        throw new ApiError(500, "Something went wrong in server")
    }
}

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

const loginUser = asyncHandler(

    async (req, res) => {

        const { username, password, email } = req.body;

        if (!(username || email)) {
            throw new ApiError(400, "username or email is required")
        }

        const user = await User.findOne({
            $or: [{ username }, { email }]
        })

        if (!user) {
            throw new ApiError(404, "user does not exist")
        }

        const isPasswordValid = await user.isPasswordCorrect(password)

        if (!isPasswordValid) {
            throw new ApiError(401, "invalid user Credentials")
        }

        const { AccessToken, RefereshToken } = await generateAccessAndRefereshToken(user._id)
        const loggedInUser = await User.findById(user._id).
            select("-password -refreshToken")

        if (!loggedInUser) {
            throw new ApiError(404, "user not found")
        }
        const options = {
            httpOnly: true,
            secure: true
        }

        return res
            .status(200)
            .cookie("accessToken", AccessToken, options)
            .cookie("refereshToken", RefereshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {
                        user: loggedInUser, AccessToken, RefereshToken
                    },
                    "User logged in Successfully"
                )
            )

    }

)

const logOutUser = asyncHandler(
    async (req, res) => {

        await User.findByIdAndUpdate(
            req.user._id,
            {
                $set: {
                    refreshToken: undefined
                }

            }
        )

        const options = {
            httpOnly: true,
            secure: true
        }
        return res.
            status(200).
            clearCookie("accessToken", options).
            clearCookie("refereshToken", options).
            json(new ApiResponse(200, {}, "usser logged Out"))




    }
)


const refreshAccessToken = asyncHandler(

    async (req, res) => {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized token request")
        }

        try {
            const decodedToken = jwt.verify(
                incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET
            )

            const user = await User.findById(decodedToken?._id)

            if (!user) {
                throw new ApiError(401, "Invalid refresh token")
            }

            if (incomingRefreshToken !== user?.refreshToken) {
                throw new ApiError(401, "refereshToken is expired or used")
            }

            const options = {
                httpOnly: true,
                secure: true
            }

            const { AccessToken, RefereshToken } = await generateAccessAndRefereshToken(user._id)

            return res.status(200).
                cookie("accessToken", AccessToken, options).
                cookie("refereshToken", RefereshToken, options)
                .json(
                    new ApiResponse(200, { AccessToken, RefereshToken }, "Access token refereshed")
                )
        } catch (error) {
            throw new ApiError(401, error?.message || "invalid referesh token")
        }
    }

)
export { registerUser, loginUser, logOutUser ,refreshAccessToken}