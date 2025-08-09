class ApiError extends Error {
    constructor(
        statusCode,
        message = "Something went wrong",
        errors = [],
        stack = ""
    ) {
        super(message)
        this.statusCode = statusCode
        this.data = null
        this.message = message
        this.success = false;
        this.errors = errors

        if (stack) {
            this.stack = stack
        } else {
            Error.captureStackTrace(this, this.constructor)
        }

    }
}

export { ApiError }



//same work with functions -->



// const apiError = (statusCode, message, errors = []) => {
//     return {
//         success: false,
//         statusCode,
//         message,
//         errors
//     };
// };

// export { apiError };