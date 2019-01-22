import mysql from 'mysql2/promise';
import {database as config} from '../config';
import {saltSize, keySize} from './crypto';

const pool = mysql.createPool({
    host: config.hostname,
    port: config.port,
    user: config.username,
    password: config.password,
    supportBigNumbers: true,
    bigNumberStrings: true,
    connectionLimit: 10
});

export async function init(reset=false) {
    let conn = await pool.getConnection();
    try{
        if(reset){
            await conn.query(`
                DROP DATABASE IF EXISTS todo
            `);
        }
        await conn.query(`
            CREATE DATABASE IF NOT EXISTS todo
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS todo.users (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                firstName VARCHAR(255),
                lastName VARCHAR(255),
                username VARCHAR(255) NOT NULL,
                password BINARY(${keySize}) NOT NULL,
                salt BINARY(${saltSize}) NOT NULL,
                PRIMARY KEY(id),
                UNIQUE(username)
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS todo.sessions (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                userId BIGINT UNSIGNED NOT NULL,
                expirationDate DATETIME NOT NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(userId)
                  REFERENCES todo.users(id)
                  ON UPDATE CASCADE
                  ON DELETE CASCADE
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS todo.lists (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                PRIMARY KEY(id)
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS todo.items (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                listId BIGINT UNSIGNED NOT NULL,
                name VARCHAR(255) NOT NULL,
                description VARCHAR(1024),
                state ENUM('in-progress', 'complete', 'canceled') DEFAULT 'in-progress' NOT NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(listId) 
                    REFERENCES todo.lists(id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS todo.permissions (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                userId BIGINT UNSIGNED,
                listId BIGINT UNSIGNED NOT NULL,
                role ENUM('owner', 'write', 'read') NOT NULL,
                PRIMARY KEY(id),
                UNIQUE(userId, listId),
                FOREIGN KEY(userId) 
                    REFERENCES todo.users(id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE,
                FOREIGN KEY(listId) 
                    REFERENCES todo.lists(id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE
            )
        `);
    }catch(ex){
        ex.message = 'Database init failed: ' + ex.message;
        throw ex;
    }finally{
        conn.release();
    }
}

export async function getConnection() {
    return await pool.getConnection();
}

export async function releaseConnection(conn) {
    conn.release();
}

async function purge() {
    let db = await getConnection();
    try{
        let [results] = await db.query(
            `DELETE FROM todo.sessions WHERE expirationDate < NOW()`
        );
        if(results.affectedRows !== 0)
            console.log(`Purged ${results.affectedRows} expired sessions.`);
        [results] = await db.query(
            `DELETE FROM todo.lists WHERE id NOT IN (SELECT DISTINCT listId FROM todo.permissions)`
        );
        if(results.affectedRows !== 0)
            console.log(`Purged ${results.affectedRows} orphaned lists.`);
    }finally{
        await releaseConnection(db);
    }
}

setTimeout(() => purge().catch(console.error), 10 * 1000);
setInterval(() => purge().catch(console.error), 60 * 60 * 1000);