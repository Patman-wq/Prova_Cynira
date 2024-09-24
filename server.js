// server.js

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração do banco de dados SQLite
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Conectado ao banco de dados SQLite.');
});

// Criação da tabela de usuários, caso não exista
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ra TEXT UNIQUE,
    email TEXT UNIQUE,
    serie TEXT,
    ano INTEGER,
    nome TEXT,
    senha TEXT
)`);

// Rota de cadastro
app.post('/cadastro', (req, res) => {
    const { ra, email, serie, ano, nome, senha } = req.body;

    bcrypt.hash(senha, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao cadastrar o usuário' });
        }

        db.run(`INSERT INTO users (ra, email, serie, ano, nome, senha) VALUES (?, ?, ?, ?, ?, ?)`,
            [ra, email, serie, ano, nome, hash],
            function (err) {
                if (err) {
                    return res.status(400).json({ error: 'RA ou E-mail já estão cadastrados' });
                }
                res.status(201).json({ message: 'Usuário cadastrado com sucesso!' });
            }
        );
    });
});

// Rota de login
app.post('/login', (req, res) => {
    const { ra, senha } = req.body;

    db.get(`SELECT * FROM users WHERE ra = ?`, [ra], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        bcrypt.compare(senha, user.senha, (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao verificar a senha' });
            }
            if (!result) {
                return res.status(401).json({ error: 'Senha incorreta' });
            }

            res.status(200).json({ message: 'Login bem-sucedido', user });
        });
    });
});

// Inicie o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
