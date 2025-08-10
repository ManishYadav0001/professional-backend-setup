const asyncHandler = (func) => async (req, res, next) => {

    try {

        return await func(req, res, next)
    } catch (error) {

        return res.status(error.statusCode || 500).json({
            success: false,
            message: error.message
        })
    }

}

export { asyncHandler }

























// const aasyncHandler = (func) => async (req, res, next) => {

//     try {
//         return await func(req, res, next)
//         next();
//     } catch (error) {

//     }

// }