require('dotenv').config(); // variáveis de ambiente
const express = require('express');
const sqlite3 = require('sqlite3').verbose(); // SGBD utilizado (SQLite3)
const path = require('path');
const jwt = require('jsonwebtoken'); // Para geração de tokens de acesso

const chaveSecreta = "segredo"; // para geração de tokens de acesso

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", 'public')));

// Conecta a aplicação ao banco de dados SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (!err) {
        console.log("Conectado ao BD!");
    }
});

////// - ROTAS - //////

// Tela de login
app.get('/login', (req, res) => {
    res.render("../views/login.ejs");
});

// Todas as rotas abaixo checam o token para garantir
// que o usuário tem autorização para ver a página.

// Painel do administrador
app.get('/admin',(req, res) => {
    const token = req.query.token;

    // checa a validade do token e se ele existe
    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                // se o token estiver válido, redirecionar ao painel
                return res.render("../views/admin.ejs");
            }
        });
    }

    // caso contrário, redirecionar à tela de login
    // essa mesma verificação é repetida nas páginas abaixo
    return res.render('../views/login.ejs');
});

// Painel do cliente
app.get('/cliente', (req, res) => {
    const token = req.query.token;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                return res.render("../views/cliente.ejs");
            }
        });
    }
    return res.render('../views/login.ejs');
});

// Informações do cliente
app.get('/cliente-info', (req, res) => {
    const token = req.query.token;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                return res.render("../views/cliente-info.ejs");
            }
        });
    }
    return res.render('../views/login.ejs');
});

// Aba de progresso do cliente
app.get('/cliente-progresso', (req, res) => {
    const token = req.query.token;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                return res.render("../views/cliente-progresso.ejs");
            }
        });
    }
    return res.render('../views/login.ejs');
});

// Aba de exercícios e instrutor do cliente
app.get('/cliente-treinos', (req, res) => {
    const token = req.query.token;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                return res.render("../views/cliente-treinos.ejs");
            }
        });
    }
    return res.render('../views/login.ejs');
});

// Criação de cadastro
app.get('/admin-criar', (req, res) => {
    const token = req.query.token;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                return res.render("../views/admin-criar.ejs");
            }
        });
    }
    return res.render('../views/login.ejs');
});

// Edição de cadastro existente
app.get('/admin-editar', (req, res) => {
    const token = req.query.token;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                return res.render("../views/admin-editar.ejs");
            }
        });
    }
    return res.render('../views/login.ejs');
});

// Método para alterar (adicionar, atualizar e deletar) o banco de dados
app.post('/alterar-db', (req, res) => {
    const { token, query } = req.body;

    if (token) {
        jwt.verify(token, chaveSecreta, (err) => {
            if (!err) {
                db.run(query);
                return res.status(200).json({message: "Alterado"});
            }
        });
    }
});

// Método para ler o banco e dados
app.post('/ler-db', async (req, res) => {
    const { token, query } = req.body;

    if (!token) {
        // se não há token, redirecionar à página de login
        return res.render('../views/login.ejs');
    }

    try {
        // Verifica a validade do token dado
        await new Promise((resolve, reject) => {
            jwt.verify(token, chaveSecreta, (err) => {
                if (err) reject("Token inválido");
                else resolve();
            });
        });

        // Se o token for válido, rodar a pesquisa
        const result = await new Promise((resolve, reject) => {
            db.get(query, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        // se tudo deu certo, retornar o resultado da pesquisa
        return res.json(result);

    } catch (error) {
        // se houve um erro, deslogar o usuário
        console.error("Error:", error);
        return res.render('../views/login.ejs');
    }
});


// Método para checar a validade de tentativa de login
app.post('/login', (req, res) => {

    // Credenciais
    const { usuario, senha } = req.body;
        
    if (!usuario || !senha) {
        return res.status(400).json({ message: 'Um dos campos é nulo'});
    }
    
    const query = 'SELECT * FROM Cliente WHERE usuario = ? AND senha = ? LIMIT 1';
    
    db.get(query, [usuario, senha], (err, result) => {

        if (err) {
            return res.status(500);
        }
        
        // Se as credenciais estiverem corretas, gerar token 
        // e enviar para o usuário. Caso contrário, impedir o acesso.
        if (result) {
            // cria uma token de acesso que expira em 30 minutos
            return res.json({ token: jwt.sign({ usuario: result.usuario }, chaveSecreta, { expiresIn: '30m' }) });
        } else {
            return res.status(400).json({message: "Credenciais inválidas!"});
        }

    });

});

// Rota alternativa para chegar na página de login
app.get('/', (req, res) => {
    res.render("../views/login.ejs");
});

////////////////////////

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));
app.use(express.json());
module.exports = db;