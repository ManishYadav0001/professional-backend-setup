class ApiResponse {
    constructor(
        statusCode,
        data,
        message = "Success"
    ) {
        this.statusCode = statusCode
        this.data = data
        this.message = message
        this.success = statusCode < 400
    }
}


export { ApiResponse }




// same work with function -->

// const apiResponse = (statusCode, data, message = "Success") => {
//     return {
//         success: true,
//         statusCode,
//         data,
//         message
//     };
// };

// export { apiResponse };