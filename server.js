// Подключение модулей
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const app = express();

// Настройка сессий
app.use(session({
    secret: 'секретный_ключ', // Замените на случайную строку
    resave: false,
    saveUninitialized: false
}));

// Настройка парсинга POST-запросов
app.use(express.urlencoded({ extended: true }));

// Подключение статики
app.use(express.static('public'));

// Настройка шаблонов
app.set('view engine', 'ejs');

// Подключение базы данных
const db = new sqlite3.Database('./database.db');

// Создаем таблицу пользователей (если не существует)
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )`);
});

const adminName = 'SoltanAlikhan';
const adminPass = 'Lenovo135';


bcrypt.hash(adminPass, 10, (err, hash) => {
    if (err) throw err;
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, [adminName, hash]);
});

// Создаем таблицу для контента (если не существует)
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS content (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL
    )`);

    // Добавляем начальный контент (если таблица пустая)
    db.get(`SELECT COUNT(*) AS count FROM content`, (err, row) => {
        if (err) throw err;
        if (row.count === 0) {
            db.run(`INSERT INTO content (title, body) VALUES (?, ?)`, 
                ['Заголовок по умолчанию', 'Начальный текст. Отредактируйте его в админке.']);
        }
    });
});

// Middleware для защиты маршрутов
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Главная страница (динамический контент)
// Главная страница для админа (защищена)
app.get('/', requireAuth, (req, res) => {
    db.get(`SELECT * FROM content WHERE id = 1`, (err, content) => {
        if (err) throw err;
        res.render('index', { content });
    });
});

// Страница регистрации
app.get('/register', requireAuth, (req, res) => {
    res.render('register');
});

// Обработка регистрации
app.post('/register', requireAuth, (req, res) => {
    const { username, password } = req.body;

    // Проверка на существование пользователя
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) throw err;

        if (user) {
            return res.send('Такой админ уже существует!');
        }

        // Хешируем пароль
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Добавляем нового админа
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
            [username, hashedPassword], 
            (err) => {
                if (err) throw err;
                res.redirect('/users');
            }
        );
    });
});

// Удаление админа
app.post('/delete-user/:id', requireAuth, (req, res) => {
    const adminId = req.params.id;

    // Проверка: нельзя удалить себя
    if (req.session.userId == adminId) {
        return res.send('Вы не можете удалить свой аккаунт!');
    }

    // Удаление пользователя
    db.run('DELETE FROM users WHERE id = ?', [adminId], (err) => {
        if (err) throw err;
        res.redirect('/users');
    });
});

// Страница со списком всех админов
// Страница со списком всех админов
app.get('/users', requireAuth, (req, res) => {
    db.all('SELECT id, username FROM users', (err, users) => {
        if (err) throw err;
        res.render('users', { users, userId: req.session.userId });
    });
});


// Страница редактирования контента (защищена)
app.get('/edit', requireAuth, (req, res) => {
    db.get(`SELECT * FROM content WHERE id = 1`, (err, content) => {
        if (err) throw err;
        res.render('edit', { content });
    });
});

// Обработка изменений контента
app.post('/edit', requireAuth, (req, res) => {
    const { title, body } = req.body;
    db.run(`UPDATE content SET title = ?, body = ? WHERE id = 1`, [title, body], (err) => {
        if (err) throw err;
        res.redirect('/');
    });
});

// Главная страница для посетителей
app.get('/public', (req, res) => {
    db.get(`SELECT * FROM content WHERE id = 1`, (err, content) => {
        if (err) throw err;
        res.render('public', { content });
    });
});


// Страница входа
app.get('/login', (req, res) => {
    res.render('login');
});

// Обработка входа
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) throw err;
        if (user) {
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) throw err;
                if (isMatch) {
                    req.session.userId = user.id;
                    res.redirect('/');
                } else {
                    res.send('Неверный пароль.');
                }
            });
        } else {
            res.send('Пользователь не найден.');
        }
    });
});

// Выход
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});
