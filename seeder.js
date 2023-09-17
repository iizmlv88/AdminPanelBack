const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

mongoose.connect('mongodb+srv://iizmlv88:THINKfast999@cluster.35qlanq.mongodb.net/admin_panel_back?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = require('./modules/User'); 
const Role = require('./modules/Role'); 

async function seed() {
  try {
    const administratorRole = await Role.findOne({ value: 'ADMINISTRATOR' });
    if (!administratorRole) {
      await new Role({ value: 'ADMINISTRATOR' }).save();
    }

    const newUser = {
      password: bcrypt.hashSync('123456789', 10), 
      firstname: 'god',
      lastname: 'godov',
      email: 'god@gmail.com',
      confirmPassword: '123456789',
      gender: 'male',
      phoneNumber: '123456789',
      isActivated: true,
      roles: ['ADMINISTRATOR'], 
    };

    const user = new User(newUser);
    await user.save();

    console.log('Користувач з роллю ADMINISTRATOR створено, email: god@gmail.com, password: 123456789');
    mongoose.connection.close();
  } catch (error) {
    console.error('Помилка під час створення користувача:', error);
  }
}

seed();