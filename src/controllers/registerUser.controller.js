import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiErrors.js";
import { User } from "../models/user.model.js";
import { uploadCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken";
import { v2 as cloudinary } from "cloudinary";
import mongoose from "mongoose";

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
            "-password -refreshToken"
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
            .cookie("refreshToken", RefereshToken, options)
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
            clearCookie("refreshToken", options).
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
                throw new ApiError(401, "refreshToken is expired or used")
            }

            const options = {
                httpOnly: true,
                secure: true
            }

            const { AccessToken, RefereshToken } = await generateAccessAndRefereshToken(user._id)

            return res.status(200).
                cookie("accessToken", AccessToken, options).
                cookie("refreshToken", RefereshToken, options)
                .json(
                    new ApiResponse(200, { AccessToken, RefereshToken }, "Access token refereshed")
                )
        } catch (error) {
            throw new ApiError(401, error?.message || "invalid referesh token")
        }
    }

)

const changeCurrentPassword = asyncHandler(
    async (req, res) => {

        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            throw new ApiError(401, "passwords are required")
        }




        const userId = req.user._id;

        const user = await User.findById(
            userId
        );

        const isPasswordValid = await user.isPasswordCorrect(currentPassword)

        if (!isPasswordValid) {
            throw new ApiError(401, "current password is incorrect")
        }

        if (!user) {
            throw new ApiError(404, "user not found")
        }

        user.password = newPassword;
        await user.save({ validateBeforeSave: false })

        return res.status(200).json(
            new ApiResponse(200, {}, "Pasword changed successfully")
        )

    }
)

const getCurrentUser = asyncHandler(
    async (req, res) => {

        return res.status(200).json(
            new ApiResponse(200, req.user, "current user fetched successfully")
        )
    }
)

const updateAccountDetails = asyncHandler(
    async (req, res) => {

        const { fullName, email } = req.body;

        if (!fullName || !email) {
            throw new ApiError(400, "full info is. required")
        }
        const userId = req.user._id;

        const user = await User.findByIdAndUpdate(
            userId,
            {
                $set: {
                    fullName,
                    email
                }
            },
            { new: true }
        ).select("-password")

        return res.status(200).json(
            new ApiResponse(200, user, "User info updated successfully")
        )

    }
)

const updateUserAvatar = asyncHandler(
    async (req, res) => {

        try {

            const currentuserId = req.user._id;

            const currentUserAvatar = await User.findById(currentuserId).select("avatar");

            if (!currentUserAvatar || !currentUserAvatar.avatar) {
                throw new ApiError(404, "current user avatar not found")
            }

            const publicId = currentUserAvatar.avatar.split("/").pop().split(".")[0];

            await cloudinary.uploader.destroy(publicId)

        } catch (error) {
            throw new ApiError(500, "Can't able to delete previous avatar image from cloudanary")
        }



        const avatarLocalPath = req.files?.avatar?.[0]?.path;

        if (!avatarLocalPath) {
            throw new ApiError(400, "avatar not found")
        }

        const Avatar = await uploadCloudinary(avatarLocalPath)

        if (!Avatar.url) {
            throw new ApiError(500, "can't upload avatar")
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            {
                $set: {
                    avatar: Avatar?.url
                }
            },
            { new: true }
        ).select("-password")



        return res.status(200).json(
            new ApiResponse(200, user, "Avatar updated successfully")
        )

    }
)

const updateUserCoverimage = asyncHandler(
    async (req, res) => {


        try {

            const currentUserCoverImage = await User.findById(req.user._id).select("coverimage")


            if (!currentUserCoverImage || !currentUserCoverImage.coverimage) {
                throw new ApiError(404, "current user coverimage not found");
            }

            const publicId = currentUserCoverImage.coverimage.split("/").pop().split(".")[0];

            await cloudinary.uploader.destroy(publicId)


        } catch (error) {
            throw new ApiError(500, "Can't able to delete previous coverImage image from cloudanary")

        }


        const coverImageLocalPath = req.files?.coverimage?.[0]?.path;

        if (!coverImageLocalPath) {
            throw new ApiError(400, "coverImage not found")
        }

        const coverImage = await uploadCloudinary(coverImageLocalPath)

        if (!coverImage.url) {
            throw new ApiError(500, "can't upload coverImage")
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            {
                $set: {
                    coverimage: coverImage?.url
                }
            },
            { new: true }
        ).select("-password")

        return res.status(200).json(
            new ApiResponse(200, user, "coverImage updated successfully")
        )

    }
)



const GettingChannelData = asyncHandler(
    async (req, res) => {
        const { username } = req.params;

        if (!username) {
            throw new ApiError(404, "can't fetch username")
        }

        const channel = await User.aggregate([
            {
                $match: {
                    username: username?.toLowerCase()
                }
            },
            {
                $lookup: {
                    from: "subscription",
                    localField: "_id",
                    foreignField: "channel",
                    as: "subscribers"
                }
            },
            {
                $lookup: {
                    from: "subscription",
                    localField: "_id",
                    foreignField: "subscriber",
                    as: "subscribedTo"
                }
            },
            {
                $addFields: {
                    subscriberCount: {
                        $size: "$subscribers"
                    },
                    subscribedToCount: {
                        $size: "$subscribedTo"
                    },
                    isSubscribed: {
                        $cond: {
                            if: { $in: [req.user?._id, "$subscribers.subscriber"] },
                            then: true,
                            else: false
                        }
                    }

                }
            }
            ,
            {
                $project: {
                    fullName: 1,
                    username: 1,
                    subscriberCount: 1,
                    subscribedToCount: 1,
                    isSubscribed: 1,
                    avatar: 1,
                    coverimage: 1,
                    email: 1
                }
            }
        ])
        if (!channel?.length) {
            throw new ApiError(404, "channel does not exists")
        }

        return res.status(200).
            json(new ApiResponse(200, channel[0], "user channel fetched successfully"))
    }
)

const getWatchHistory = asyncHandler(
    async (req, res) => {

        const user = await User.aggregate([

            {
                $match: {
                    _id: new mongoose.Types.ObjectId(req.user._id)
                }
            },
            {
                $lookup: {
                    from: "videos",
                    localField: "watchHistory",
                    foreignField: "_id",
                    as: "watchHistory",
                    pipeline: [
                        {
                            $lookup: {
                                from: "users",
                                localField: "owner",
                                foreignField: "_id",
                                as: "owner",
                                pipeline: [{
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }]
                            }
                        },
                        {
                            $addFields: {
                                owner: {
                                    $first: "$owner"
                                }
                            }
                        }
                    ]
                }
            }
        ])

        return res
            .status(200)
            .json(
                new ApiResponse(200
                    , user[0].watchHistory
                    , "User watch history fetched successfully"))

    }
)


export {
    registerUser
    , loginUser
    , logOutUser
    , refreshAccessToken
    , changeCurrentPassword
    , getCurrentUser
    , updateAccountDetails
    , updateUserAvatar
    , updateUserCoverimage
    , GettingChannelData
    , getWatchHistory
}