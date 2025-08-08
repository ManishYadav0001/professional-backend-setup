import mongoose from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";


const videoSchema = mongoose.Schema(
    {
        videoFile: {
            type: String, // url from cloudnary
            require: true

        },

        thumbnail: {
            type: String, // url from cloudnary
            require: true

        },

        description: {
            type: String,
            require: true

        },
        title: {
            type: String,
            require: true

        },
        views: {
            type: Number,
            default: 0
        },
        duration: {
            type: Number,
            required: true
        },
        isPublished: {
            type: Boolean,
            default: true
        },
        owner: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        }

    },

    { timestamps: true }
)

videoSchema.plugin(mongooseAggregatePaginate)

export const Video = mongoose.model("Video", videoSchema)