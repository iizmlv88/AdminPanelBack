const { Schema, model } = require('mongoose');

const User = new Schema({
    password: { type: String, require: true },
    roles: [{ type: String, ref: 'Role'}],
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    isActivated: {type: Boolean, default: false},
    confirmPassword: { type: String, required: true },
    gender: { type: String, required: true },
    phoneNumber: { type: String, required: true }
    
});

module.exports = model('User', User);
