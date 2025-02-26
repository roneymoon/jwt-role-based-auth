const mongoose = require("mongoose")
require("dotenv").config()

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('🔥 MongoDB Connected'))
.catch(err => console.log('❌ DB Connection Error:', err));

