const User = require('./modules/User');
const Role = require('./modules/Role');
const bcrypt = require('bcrypt');
const Token = require('./modules/Token')
const News = require('./modules/News');
const generator = require('generate-password')

const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { hash_password, jwt_access_secret, jwt_refresh_secret, smtp_host, smtp_password, smtp_port, smtp_user } = require('./config');
const nodemailer = require('nodemailer');

const genereteAccessAndRefreshToken = (id, email, firstname, lastname, gender, phoneNumber, roles) => {
    const payload = {
        id,
        firstname,
        lastname,
        email,
        gender,
        phoneNumber,
        roles
    };
    const accessToken = jwt.sign(payload, jwt_access_secret, { expiresIn: '1h' });
    const refreshToken = jwt.sign(payload, jwt_refresh_secret, { expiresIn: '3d' });
    return {
        accessToken,
        refreshToken
    }
};
class authController {
    async registration(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ message: 'помилка реєстрації', errors: errors.array() });
            }

            const { email, password, role } = req.body;
            const candidate = await User.findOne({ email });
            if (candidate) {
                return res.status(400).json({ message: 'користувач з таким іменем вже існує' });
            }
            const hashPassword = bcrypt.hashSync(password, hash_password);

             const userRole = await Role.findOne({ value: role });
            // const userRole = await Role.findOne({ value: 'USER' });

            // const userRole = await Role.findOne({value: 'ADMINISTRATOR'})

            const user = new User({
                password: hashPassword,
                roles: [userRole.value],
                firstname: req.body.firstname,
                lastname: req.body.lastname,
                email: req.body.email,
                confirmPassword: req.body.confirmPassword,
                gender: req.body.gender,
                phoneNumber: req.body.phoneNumber
            });
            await user.save();

            const transporter = nodemailer.createTransport( {
                host: smtp_host,
                port: smtp_port,
                service: 'gmail',
                secure: false,
                auth: {
                    user: smtp_user,
                    pass: smtp_password
                },
                tls: {
                    rejectUnauthorized: false,
                },
            })

            const activationLink = `http://localhost:5000/api/User/activate/${user._id}`

            const mailOptions = {
                to: email,
                from: smtp_user,
                subject: 'activate your account',
                text: `дякуэмо за рээстрацію. активуйте свій акаунт перейшовши за посиланням \n\n  ${activationLink}\n\n якщо ви не реєструвалися на нашому сайті проігноруйте цей лист.`,
                
            }

            transporter.sendMail(mailOptions, (err)=>{
                if (err) {
                    console.log(err);
                    return res.status(500).json({message: 'не вдалося надісо=лати лист для активації'})
                }
                return res.json({message: 'лист для активації надіслано на вашу адресу'})
            })

            // return res.json({ message: 'користувач успішно зареєстрований' });
        } catch (error) {
            console.log(error);
            res.status(400).json({ message: 'reg er' });
        }
    }

    async login(req, res) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ message: `korustyvachs ${email} ne isnye` });
            }

            if(!user.isActivated){
                return res.status(400).json({ message: `ваш оакаунт не активовано` });
            }
            
            const validPassword = bcrypt.compareSync(password, user.password);
            if (!validPassword) {
                return res.status(400).json({ message: `nevirnuy parol` });
            }

            const {accessToken, refreshToken} = genereteAccessAndRefreshToken(user._id, user.firstname, user.lastname, user.email, user.gender, user.phoneNumber, user.roles);

            let refresh = await Token.findOne( {user: user._id})
            if (!refresh) {
                refresh = new Token({user: user._id, refreshToken})
            } else {
                refresh.refreshToken = refreshToken
            }

            // const refresh = new Token({user: user._id, refreshToken})
            // refresh.save()
            await refresh.save()
            return res.json({ accessToken, refreshToken });
        } catch (error) {
            console.log(error);
            return res.status(400).json({ message: 'login er' });
        }
    }

    async getUsers(req, res) {
        try {
            const users = await User.find();
            res.json(users);
        } catch (error) {
            console.log(error);
            return res.status(400).json({ message: 'getUsers er' });
        }
    }
 
async deleteUser(req, res) {
    try {
        const { id } = req.params;

        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) {
            return res.status(404).json({ message: 'Користувача не знайдено' });
        }

        return res.json({ message: 'Користувача успішно видалено', deletedUser });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: 'Помилка видалення користувача' });
    }
}

async RefreshToken(req, res) {
    try {
        const { refreshToken } = req.body;
        const existiogToken = await Token.findOne({refreshToken})
        if (!existiogToken) {
            return res.status(401).json({message: 'невірний фбо не дійсний рефреш токен'})
        }
        const decodedPayload = jwt.verify(refreshToken, jwt_refresh_secret)

        const {accessToken, refreshToken: newRefreshToken} = genereteAccessAndRefreshToken(
            decodedPayload.id,
            decodedPayload.firstname,
            decodedPayload.lastname,
            decodedPayload.email,
            decodedPayload.gender,
            decodedPayload.phoneNumber,
            decodedPayload.roles
            )
        
            existiogToken.refreshToken = newRefreshToken
            await existiogToken.save()
        
        return res.json({ accessToken, refreshToken: newRefreshToken });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: 'Помилка token error' });
    }
}

async logout(req, res) {
    try {
        const { userId } = req.body;

        const token = await Token.findOneAndDelete( {user: userId})
        if(!token){
            return res.status(400).json({message: 'користувача не знайдено з таким айді'})
        }

        return res.json({message: 'ви вийшли з системи'});
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: 'logout error' });
    }
}

async changePassword(req, res) {
    try {
        const { userId, currentPassword, newPassword, confirmNewPassword } = req.body;

         const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const user = await User.findById(userId)
        console.log(userId, currentPassword, newPassword, confirmNewPassword );
        if(!user){
            return res.status(400).json({message: 'користувача не знайдено'})
        }
        const validPassword = bcrypt.compareSync(currentPassword, user.password)
        if(!validPassword){
            return res.status(400).json({message: 'невірний поточний пароль'})
        }

        const newHashedPassowrd = bcrypt.hashSync(newPassword, hash_password)

        user.password = newHashedPassowrd
        await user.save()

        return res.json({message: 'пароль змінено'});
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: 'changePassword error' });
    }
}

  async createNews(req, res) {
    try {
      const { title, content } = req.body;
      const news = new News({ title, content });
      await news.save();
      return res.json({ message: 'Новину створено успішно' });
    } catch (error) {
      console.error(error);
      return res.status(400).json({ message: 'Помилка створення новини' });
    }
  }
async updateUser(req, res) {
    try {
        const { userId, firstname, lastname, email, gender, phoneNumber } = req.body;
        
        if (!req.user.roles.includes('ADMINISTRATOR')) {
            return res.status(403).json({ message: 'У вас немає прав на оновлення користувача' });
        }
        
        const user = await User.findByIdAndUpdate(
            userId,
            {
                firstname,
                lastname,
                email,
                gender,
                phoneNumber
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ message: 'Користувача не знайдено' });
        }

        return res.json({ message: 'Користувача успішно оновлено', user });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: 'Помилка оновлення користувача' });
    }
}

async activate(req, res) {
        try {
            const { userId } = req.params

            const user = await User.findById( userId)

            if(!user || user.isActivated){
                return res.status(400).json({message: 'невірний айді користувача або обліковий запис вже активний'})
            }

            user.isActivated = true
            await user.save()

            return res.status(400).json({message: 'обліковий запис вже активний , тепер ви можете здійснити вхід'})

        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'server er' });
        }
    }

async forgotPassword(req, res) {
    try {
        const { email } = req.body
        const user = await User.findOne({email})
        if (!user) {
            return res.status(400).json({ message: 'уористувача з таким емейлом не знайдено error' });
        }
        const newPassword = generator.generate({
            length: 10,
            numbers: true,
            symbols: true
        })

        const hashPassword = bcrypt.hashSync(newPassword, hash_password)

        user.password = hashPassword
        await user.save()

        const transporter = nodemailer.createTransport({
            host: smtp_host,
            port: smtp_port,
            service: 'gmail',
            secure: false,
            auth:{
                user: smtp_user,
                pass: smtp_password,
            },
            tls: {
                rejectUnauthorized: false
            }
        })

        const mailOptions = {
            to: email,
            from: smtp_user,
            subject: 'відновлення пароля',
            text: "",
            html:
            `
            <h3 style='font-size: 28px;'>Ваш новий пароль</h3>
            <h1 style= '
            padding: 10px;
            text-align: center;
            background-color: silver;
            border-radius: 12px;
            border: 3px solid black;
            width: 170px;'>${newPassword}</h1>
            <h4 style = '
            font-size: 22px;
            color: red;
            '> рекомендуємо піял того як ви ввійдете , замінити пароль</h4>
            `
        }

        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                 return res.status(500).json({ message: 'не вдалосґя відправити емейл' });
            }
            return res.status(500).json({ message: 'новий пароль відправлено на Вашу пошту' });
        })
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'відновлення пароля error' });
    }
}



}

module.exports = new authController();
