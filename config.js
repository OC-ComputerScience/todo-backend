module.exports = {
    server: {
        hostname: 'localhost',
        port: 8081,
        secretKey: Buffer.from('xT1tdO3CfMH01pjxC+guN1LWSt2nKvr5td6KUpw7Czg=', 'base64')
    },
    database: {
        hostname: 'localhost',
        port: 3306,
        username: 'root',
        password: '7^Ooc*iJHI5*IDVW',
        database: 'todo',
        autoInit: false
    },
    tokenLifetime: 24*60*60*1000
};