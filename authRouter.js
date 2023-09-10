const Router = require('express')
const router = new Router()
const controller = require('./authController')

const {check} = require('express-validator')

const authMiddleware = require('./middlewares/authMiddleware')
const roleMiddleware = require('./middlewares/roleMiddleware')

router.post('/changePassword',
    [
        check('userId', 'Поле userId обовязкове').notEmpty(),
        check('currentPassword', 'Поле currentPassword обовязкове').notEmpty(),
        check('newPassword', 'Поле newPassword має містити мінімум 8 символів').isLength({ min: 8 }),
        check('confirmNewPassword', 'Поле confirmNewPassword обовязкове').notEmpty(),
        check('confirmNewPassword', 'Поле confirmNewPassword повинно бути ідентичним з newPassword').custom((value, { req }) => value === req.body.newPassword)
    ],
    authMiddleware,
    controller.changePassword
);




router.post('/registration', 
[
    check('password', 'пароль може мати мінімум 8 і максимум 16 символів').isLength({ min: 8, max: 16 }),
    check('firstname', 'імя користувача є обовязковим').notEmpty(),
    check('lastname', 'прізвище користувача є обовязковим').notEmpty(),
    check('email', 'введіть коректний формат електронної пошти').isEmail(),
    check('confirmPassword', 'поле підтвердження паролю обовязкове').notEmpty(),
    check('confirmPassword', 'підтвердження паролю має бути ідентичним з паролем').custom((value, { req }) => value === req.body.password),
    check('gender', 'стать користувача є обовязковою').notEmpty(),
    check('phoneNumber', 'номер телефону користувача є обовязковим').notEmpty()
],
// !
router.post(
  '/createNews',
  [
    check('title', 'Заголовок новини обовязковий').notEmpty(),
    check('content', 'Зміст новини обовязковий').notEmpty(),
  ],
  authMiddleware,
  roleMiddleware(['ADMINISTRATOR']),
  controller.createNews
),
// !





authMiddleware, roleMiddleware(['ADMINISTRATOR']), controller.registration)
router.post('/login', controller.login)
router.get('/users', authMiddleware, roleMiddleware(['ADMINISTRATOR']), controller.getUsers)

router.delete('/deleteUser/:id', authMiddleware, roleMiddleware(['ADMINISTRATOR']), controller.deleteUser);


router.post('/refresh', controller.refresh);

router.post('/logout', controller.logout)

router.post('/changePassword', authMiddleware,  controller.changePassword)





module.exports = router