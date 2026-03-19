const mysql = require('mysql2');

const connection = mysql.createPool({
    host: 'localhost',
    user: 'root',       // Default XAMPP user
    password: '',       // IMPORTANT: Leave this EMPTY string '' for XAMPP
    database: 'student_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = connection;