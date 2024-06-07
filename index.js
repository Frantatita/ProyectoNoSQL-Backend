const express = require('express');
const bodyParser = require('body-parser');
const { createClient } = require('redis');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const responseTime = require('response-time');
const jwt = require('jsonwebtoken');
const client = createClient();
const app = express();

app.use(responseTime());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

client.on('connect', () => {
    console.log('Conectado a Redis');
});

client.on('error', (err) => {
    console.log('Error de conexión con Redis:', err);
});

(async () => {
    await client.connect();
})();


app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Usuario y contraseña son requeridos');
    }

    const startTime = performance.now(); // Registrando el tiempo de inicio

    try {
        // Verificar si el usuario ya está registrado en la caché
        const cachedPassword = await client.get(username);

        if (cachedPassword) {
            return res.status(409).json({ message: 'Usuario ya registrado', username });
        }

        // Si el usuario no está en la caché, registrar en la base de datos y en la caché
        const hashedPassword = await bcrypt.hash(password, 10);
        await client.hSet('users', username, hashedPassword);
        await client.set(username, hashedPassword);

        const endTime = performance.now(); // Registrar el tiempo de finalización
        const elapsedTime = endTime - startTime; // Calcular el tiempo transcurrido en milisegundos

        res.status(201).json({ message: 'Usuario registrado exitosamente', username });
    } catch (error) {
        console.error('Error registrando usuario:', error);
        res.status(500).send('Error registrando usuario');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ success: false, message: 'Username and password are required' });
    }

    const startTime = performance.now(); // Registrar el tiempo de inicio

    try {
        // Intentar recuperar la contraseña del usuario desde la caché
        let storedPassword = await client.get(username);

        if (!storedPassword) {
            console.log('Datos se almacenaron en la cache porque no estaban en ella')
            // Si no está en caché, buscar en la base de datos
            storedPassword = await client.hGet('users', username);
            if (!storedPassword) {
                return res.status(400).send({ success: false, message: 'Usuario o contraseña inválidos' });
            }

            // Almacenar la contraseña en caché para futuras consultas
            await client.set(username, storedPassword);
        }

        // Comparar contraseñas
        const isMatch = await bcrypt.compare(password, storedPassword);
        if (!isMatch) {
            return res.status(400).send({ success: false, message: 'Usuario o contraseña inválidos' });
        }

        const endTime = performance.now(); // Registrar el tiempo de finalización
        const elapsedTime = endTime - startTime; // Calcular el tiempo transcurrido en milisegundos

        const token = jwt.sign({ id: username }, 'secretKey', { expiresIn: '1h' });
        res.status(200).send({ success: true, message: 'Inicio de sesión exitoso', token });
    } catch (error) {
        console.error('Error recuperando usuario:', error);
        res.status(500).send('Error recuperando usuario');
    }
});


//Recupear los nombres de usuario
app.get('/usernames', async (req, res) => {

    try {
        // Intenta recuperar los nombres de usuarios de la memoria caché
        const cachedUsernames = await client.get('cachedUsernames');

        if (cachedUsernames) {
            console.log('Nombres de usuarios recuperados de la memoria caché');
            return res.status(200).json(JSON.parse(cachedUsernames));
        }

        // Si no hay nombres de usuarios en la memoria caché, intenta recuperarlos de la base de datos
        const usernames = await client.hKeys('users');

        if (usernames.length === 0) {
            return res.status(404).send('No se encontraron usuarios');
        }

        // Guarda los nombres de usuarios recuperados en la memoria caché para futuras consultas
        await client.set('cachedUsernames', JSON.stringify(usernames));

        console.log('Nombres de usuarios recuperados de la base de datos y almacenados en la memoria caché');
        res.status(200).json(usernames);
    } catch (error) {
        console.error('Error obteniendo los nombres de usuario:', error);
        res.status(500).send('Error obteniendo los nombres de usuario');
    }

    /*
    try {
        const usernames = await client.hKeys('users');

        if (usernames.length === 0) {
            return res.status(404).send('No se encontraron usuarios');
        }

        res.status(200).json(usernames);
    } catch (error) {
        console.error('Error obteniendo los nombres de usuario:', error);
        res.status(500).send('Error obteniendo los nombres de usuario');
    } */
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});
