import { Router } from "express";
import { changeCurrentPassword, getCurrentUser, loginUser, logOutUser, refreshAccessToken, registerUser, updateAccountDetails, updateUserAvatar, updateUserCoverimage } from "../controllers/registerUser.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "coverimage", maxCount: 1 }
  ]),
  registerUser

);

router.route("/login").post(
  loginUser
)

router.route("/logout").post(
  verifyJWT, logOutUser
)

router.route("/refresh-Token").post(
  refreshAccessToken
)
router.route("/change-password").patch(verifyJWT, changeCurrentPassword)

router.route("/current-user").get(verifyJWT, getCurrentUser)

router.route("/update-details").patch(verifyJWT, updateAccountDetails)

router.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)
router.route("/coverimage").patch(verifyJWT, upload.single("coverimage"), updateUserCoverimage)


router.route("/c/:username").get(verifyJWT, getUserChannelProfile)
router.route("/history").get(verifyJWT, getWatchHistory)

export default router;
