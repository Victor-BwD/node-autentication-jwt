require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Configurar resposta em JSON
app.use(express.json());

// Importar modelos
const User = require('./models/User');

// Rota pública
app.get('/', (req, res) => {
  res.status(200).json({ msg: "Bem vindo à API." });
});

// Middleware para verificar token
function checkToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado." });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ msg: "Token inválido." });
  }
}

// Rota privada
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  try {
    // Verificar se o usuário existe
    const user = await User.findById(id, '-password');

    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado.' });
    }

    res.status(200).json({ user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Erro ao buscar usuário." });
  }
});

// Rota de registro
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
  }

  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  if (password !== confirmPassword) {
    return res.status(422).json({ msg: "As senhas não conferem!" });
  }

  // Verificar formato de e-mail
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(422).json({ msg: "O e-mail informado é inválido!" });
  }

  try {
    // Verificar se o usuário já existe
    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(422).json({ msg: "Você já tem um cadastro com esse e-mail." });
    }

    // Criar o hash da senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Criar o usuário
    const user = new User({
      name,
      email,
      password: passwordHash,
    });

    await user.save();

    res.status(201).json({ msg: 'Usuário criado com sucesso!' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Erro ao criar usuário." });
  }
});

// Rota de login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validações
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  try {
    // Verificar se o usuário existe
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado." });
    }

    // Verificar se a senha está correta
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(422).json({ msg: "Senha inválida." });
    }

    // Gerar token de autenticação
    const secret = process.env.SECRET;
    const token = jwt.sign({ id: user._id }, secret);

    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Erro ao fazer login." });
  }
});

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://Victor:${dbPassword}@cluster0.icpi9qz.mongodb.net/`)
  .then(() => {
    app.listen(8080);
    console.log("Conexão com o banco de dados estabelecida!");
  })
  .catch((err) => console.log(err));