const { Schema, model } = require('mongoose');

const User = new Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, require: true },
    roles: [{ type: String, ref: 'Role'}],
    nameuser: { type: String, required: true },
    surname: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    confirmPassword: { type: String, required: true },
    gender: { type: String, required: true },
    phoneNumber: { type: String, required: true }
    
});

module.exports = model('User', User);
