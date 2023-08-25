const User = require ('./modules/User')
const Role = require ('./modules/Role')

const {validationResult} = require('express-validator')
const jwt = require('jsonwebtoken')
const { secret } = require('./config')

const bcrypt = require('bcrypt')


const genereteAccessToken = (id, username, roles) =>{
    const payload = {
        id,
        username,
        roles
    }
    return jwt.sign(payload, secret, { expiresIn: '1h'})
}


class authController {
    async registration(req, res){
        try {
            // validationj
            // const errors = validationResult(req)
            // if(!errors.isEmpty()){
            //     return res.status(400).json({message: 'помилка реєстрації', errors})
            // }
             const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ message: 'помилка реєстрації', errors: errors.array() });
            }
// candidat
            const {username, password} = req.body
            const condidate = await User.findOne({username})
            if(condidate){
                return res.status(400).json({message: 'користувач з таким іменем вже існує'})
            }
            // hash pas
            const hashPassword = bcrypt.hashSync(password, 8);
            const userRole = await Role.findOne({value: 'USER'})
            const nameuser = await Role.findOne({value: 'USER'})
            const surname = await Role.findOne({value: 'USER'})
            const email = await Role.findOne({value: 'USER'})
            const confirmPassword = await Role.findOne({value: 'USER'})
            const gender = await Role.findOne({value: 'USER'})
            const phoneNumber = await Role.findOne({value: 'USER'})
            // const userRole = await Role.findOne({value: 'ADMINISTRATOR'})
            const user = new User({username, password: hashPassword, roles: [userRole.value], nameuser, surname, email, confirmPassword, gender, phoneNumber})
            await user.save()
            return res.json({message: 'користувач успішно зареєстрований'})
        } catch (error) {
            console.log(error);
            res.status(400).json({message: 'reg er'})
        }
    }

    async login(req, res){
        try {
            const {username, password} = req.body
            // find user
            const user = await User.findOne({username})
            if(!user){
                return res.status(400).json({message: `korustyvachs ${username} ne isnye`})
            }
            console.log(user);
            // check password
            const validPassword = bcrypt.compareSync(password, user.password)
            if (!validPassword) {
                return res.status(400).json({message: `nevirnuy parol`})
            }
            console.log(validPassword);
            //  return res.status(400).json({message: `ok`})
            //  ctreate jqt
            const token = genereteAccessToken(user._id, user.username, user.roles)
            console.log(token);
            return res.json({token})

        } catch (error) {
            console.log(error);
            return res.status(400).json({message: 'login er'})
        }
    }

    async getUsers(req, res){
        try {

            // const userRole = new Role()
            // const adminRole = new Role({value: 'ADMINISTRATOR'})
            // await userRole.save()
            // await adminRole.save()

            res.json('server work')
        } catch (error) {
            console.log(error);
        }
    }
}

module.exports = new authController()