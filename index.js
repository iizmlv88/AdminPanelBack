const express = require('express');
const mongoose = require('mongoose')

const authRouter = require('./authRouter')

const PORT = process.env.PORT || 5000

const app = express()

app.use(express.json())
app.use('/auth', authRouter)

const start = async () => {
    try {
        mongoose.connect('mongodb+srv://iizmlv88:THINKfast999@cluster.35qlanq.mongodb.net/admin_panel_back?retryWrites=true&w=majority')
        app.listen(PORT, () => console.log(`SERVER STARTED ON PORT ${PORT}`))
    } catch (error) {
        console.log(error);
    }
}

start()