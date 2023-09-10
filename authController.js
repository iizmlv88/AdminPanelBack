const User = require('./modules/User');
const Role = require('./modules/Role');
const bcrypt = require('bcrypt');
const Token = require('./modules/Token')

// !
const News = require('./modules/News');

const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { hash_password, jwt_access_secret, jwt_refresh_secret } = require('./config');

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

            const { email, password } = req.body;
            const candidate = await User.findOne({ email });
            if (candidate) {
                return res.status(400).json({ message: 'користувач з таким іменем вже існує' });
            }
            const hashPassword = bcrypt.hashSync(password, hash_password);
            const userRole = await Role.findOne({ value: 'USER' });

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
            return res.json({ message: 'користувач успішно зареєстрований' });
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


async refresh(req, res) {
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



// !
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

}

module.exports = new authController();
