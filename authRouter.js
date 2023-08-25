const Router = require('express')
const router = new Router()
const controller = require('./authController')

const {check} = require('express-validator')

router.post('/registration', 
[
    check('username', 'імя не можу бути порожнім').notEmpty(),
    check('password', 'пароль може мати мінімум 8 і максимум 16 символів').isLength({ min: 8, max: 16 }),
    check('nameuser', 'імя користувача є обовязковим').notEmpty(),
    check('surname', 'прізвище користувача є обовязковим').notEmpty(),
    check('email', 'введіть коректний формат електронної пошти').isEmail(),
    check('confirmPassword', 'поле підтвердження паролю обовязкове').notEmpty(),
    check('confirmPassword', 'підтвердження паролю має бути ідентичним з паролем').custom((value, { req }) => value === req.body.password),
    check('gender', 'стать користувача є обовязковою').notEmpty(),
    check('phoneNumber', 'номер телефону користувача є обовязковим').notEmpty()
],
controller.registration)
router.post('/login', controller.login)
router.get('/users', controller.getUsers)



module.exports = router