import config from '../config';
import * as database from './database';
import express from 'express';
import Cors from 'cors';
import { ClientError } from './errors';
import { jsonValidate, Optional } from './validation';
import { encrypt, getSalt, hashPassword } from './crypto';
import { route, authenticate, checkPermissions } from './util';

async function start() {
    if(config.database.autoInit)
        await database.init();

    let {hostname, port} = config.server;

    const app = express();
    const cors = Cors({
        origin: true,
        credentials: true
    });
    // app.use((req, res, next) => {
    //     setTimeout(next, 1000);
    // });
    app.use(cors);
    app.use(express.json());

    app.options('*', cors);

    //region user
    app.post('/user', route(async (req, res, db) => {
        let body = req.body;
        body = jsonValidate(body, {
            firstName: new Optional('John'),
            lastName: new Optional('Doe'),
            username: 'johndoe',
            password: 'secret'
        });
        let salt = await getSalt();
        let hash = await hashPassword(body.password, salt);
        body.password = hash;
        body.salt = salt;
        let results;
        try{
            [results] = await db.query(
                `INSERT INTO todo.users SET ?`,
                [body]
            );
        }catch(err){
            if(err.code === 'ER_DUP_ENTRY'){
                throw new ClientError({
                    status: 409,
                    code: 'username-taken',
                    message: `Username already in use.`,
                    data: body.username
                });
            }
            throw err;
        }
        let userId = `${results.insertId}`;
        let expireTime = new Date(Date.now() + config.tokenLifetime);
        [results] = await db.query(
            `INSERT INTO todo.sessions(userId, expirationDate) VALUES (?, ?)`,
            [userId, expireTime]
        );
        let sessionId = `${results.insertId}`;
        let token = await encrypt({sessionId});
        return {
            status: 201,
            userId,
            token,
            expireTime
        };
    }));
    app.get('/user', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let [results] = await db.query(
            `SELECT id, firstName, lastName, username FROM todo.users WHERE id = ?`,
            [userId]
        );
        if(results.length === 0)
            throw new Error('Unexpected missing user');
        let user = results[0];
        return {user};
    }));
    app.put('/user', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let body = req.body;
        body = jsonValidate(body, {
            firstName: new Optional('John'),
            lastName: new Optional('Doe'),
            password: new Optional('secret')
        });
        if(Object.keys(body).length === 0)
            return;
        if('password' in body){
            let salt = await getSalt();
            let hash = await hashPassword(body.password, salt);
            body.password = hash;
            body.salt = salt;
        }
        let [results] = await db.query(
            `UPDATE todo.users SET ? WHERE id = ?`,
            [body, userId]
        );
        if(results.affectedRows === 0)
            throw new Error('Unexpected missing user');
    }));
    app.delete('/user', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let [results] = await db.query(
            `DELETE FROM todo.users WHERE id = ?`,
            [userId]
        );
        if(results.affectedRows === 0)
            throw new Error('Unexpected missing user');
    }));
    app.get('/user/name-taken', route(async (req, res, db) => {
        let body = req.query;
        body = jsonValidate(body, {
            username: 'johndoe'
        });
        let {username} = body;
        let [results] = await db.query(
            `SELECT TRUE as isTaken FROM todo.users WHERE username = ? UNION SELECT FALSE as isTaken`,
            [username]
        );
        let isTaken = Boolean(+results[0].isTaken);
        return {isTaken};
    }));
    //endregion
    //region auth
    app.post('/user/login', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, 'credentials');
        let expireTime = new Date(Date.now() + config.tokenLifetime);
        let [results] = await db.query(
            `INSERT INTO todo.sessions(userId, expirationDate) VALUES (?, ?)`,
            [userId, expireTime]
        );
        let sessionId = `${results.insertId}`;
        let token = await encrypt({sessionId});
        return {token, expireTime};
    }));
    app.post('/user/logout', route(async (req, res, db) => {
        let {sessionId} = await authenticate(req, db, false);
        if(sessionId == null)
            return;
        await db.query(
            `DELETE FROM todo.sessions WHERE id = ?`,
            [sessionId]
        );
    }));
    //endregion
    //region list
    app.get('/lists', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let [results] = await db.query(
            `SELECT id, name FROM todo.lists WHERE id in (SELECT listId FROM todo.permissions WHERE IF(? IS NOT NULL, userId = ?, userId IS NULL))`,
            [userId, userId]
        );
        return {lists: results};
    }));
    app.post('/list', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let body = req.body;
        body = jsonValidate(body, {
            name: 'Groceries'
        });
        let [results] = await db.query(
            `INSERT INTO todo.lists SET ?`,
            [body]
        );
        let listId = `${results.insertId}`;
        await db.query(
            `INSERT INTO todo.permissions(userId, listId, role) VALUES (?, ?, 'owner')`,
            [userId, listId]
        );
        return {
            status: 201,
            listId
        };
    }));
    app.get('/list/:listId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT id, name FROM todo.lists WHERE id = ?`,
            [listId]
        );
        if(results.length === 0)
            throw new Error('Unexpected missing list');
        let list = results[0];
        return {list};
    }));
    app.put('/list/:listId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        await checkPermissions(req, db, userId, listId, 'write');
        let body = req.body;
        body = jsonValidate(body, {
            name: new Optional('Groceries')
        });
        if(Object.keys(body).length === 0)
            return;
        let [results] = await db.query(
            `UPDATE todo.lists SET ? WHERE id = ?`,
            [body, listId]
        );
        if(results.affectedRows === 0)
            throw new Error('Unexpected missing list');
    }));
    app.delete('/list/:listId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        await checkPermissions(req, db, userId, listId, 'owner');
        let [results] = await db.query(
            `DELETE FROM todo.lists WHERE id = ?`,
            [listId]
        );
        if(results.affectedRows === 0)
            throw new Error('Unexpected missing list');
    }));
    //region list users
    app.get('/list/:listId/users', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT userId, role FROM todo.permissions WHERE listId = ?`,
            [listId]
        );
        let users = {};
        for(let user of results)
            users[user.userId] = {role: user.role};
        return {users};
    }));
    app.get('/list/:listId/user/:userId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, userId: targetUserId} = req.params;
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT role FROM todo.permissions WHERE listId = ? AND userId = ?`,
            [listId, targetUserId]
        );
        let user = results[0] || {};
        return {role: user.role};
    }));
    app.put('/list/:listId/user/:userId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let {listId, userId: targetUserId} = req.params;
        await checkPermissions(req, db, userId, listId, 'owner');
        let body = req.body;
        body = jsonValidate(body, {
            role: 'write'
        });
        if(!['owner', 'write', 'read'].includes(body.role)){
            throw new ClientError({
                code: 'invalid-role',
                message: `Unknown role '${body.role}'.`
            });
        }
        await db.query(
            `INSERT INTO todo.permissions(userId, listId, role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE role = VALUES(role)`,
            [targetUserId, listId, body.role]
        );
    }));
    app.delete('/list/:listId/user/:userId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, userId: targetUserId} = req.params;
        await checkPermissions(req, db, userId, listId, 'owner');
        await db.query(
            `DELETE FROM todo.permissions WHERE userId = ? AND listId = ?`,
            [targetUserId, listId]
        );
    }));
    //endregion
    //region list items
    app.get('/list/:listId/items', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT id, name, description, state FROM todo.items WHERE listId = ? ORDER BY id ASC`,
            [listId]
        );
        return {items: results};
    }));
    app.post('/list/:listId/item', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        await checkPermissions(req, db, userId, listId, 'write');
        let body = req.body;
        body = jsonValidate(body, {
            name: 'Apples',
            description: new Optional('For the apple pie.'),
            state: new Optional('in-progress')
        });
        if(body.state != null && !['in-progress', 'complete', 'canceled'].includes(body.state)){
            throw new ClientError({
                code: 'invalid-state',
                message: `Unknown state '${body.state}'.`
            });
        }
        body.listId = listId;
        let [results] = await db.query(
            `INSERT INTO todo.items SET ?`,
            [body]
        );
        let itemId = `${results.insertId}`;
        return {
            status: 201,
            itemId
        };
    }));
    app.get('/list/:listId/item/:itemId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, itemId} = req.params;
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT id, name, description, state FROM todo.items WHERE listId = ? AND id = ?`,
            [listId, itemId]
        );
        if(results.length === 0){
            throw new ClientError({
                code: 'missing-item',
                message: 'Item not found.'
            });
        }
        let item = results[0];
        return {item};
    }));
    app.put('/list/:listId/item/:itemId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let {listId, itemId} = req.params;
        await checkPermissions(req, db, userId, listId, 'write');
        let body = req.body;
        if(Object.keys(body).length === 0)
            return;
        body = jsonValidate(body, {
            name: new Optional('Apple'),
            description: new Optional('For the apple pie.'),
            state: new Optional('in-progress')
        });
        if(body.state != null && !['in-progress', 'complete', 'canceled'].includes(body.state)){
            throw new ClientError({
                code: 'invalid-state',
                message: `Unknown state '${body.state}'.`
            });
        }
        let [results] = await db.query(
            `UPDATE todo.items SET ? WHERE listId = ? AND id = ?`,
            [body, listId, itemId]
        );
        if(results.affectedRows === 0){
            throw new ClientError({
                code: 'missing-item',
                message: 'Item not found.'
            });
        }
    }));
    app.delete('/list/:listId/item/:itemId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, itemId} = req.params;
        await checkPermissions(req, db, userId, listId, 'write');
        let [results] = await db.query(
            `DELETE FROM todo.items WHERE listId = ? AND id = ?`,
            [listId, itemId]
        );
        if(results.affectedRows === 0){
            throw new ClientError({
                code: 'missing-item',
                message: 'Item not found.'
            });
        }
    }));
    //endregion
    //endregion

    app.use((err, req, res, next) => {
        if(err instanceof ClientError){
            res.status(err.status)
                .set(err.headers)
                .send({
                    success: false,
                    code: err.code,
                    message: err.message,
                    data: err.data
                });
        }else{
            console.error(err);
            res.status(500)
                .send({
                    success: false,
                    code: 'internal-error',
                    message: 'Internal error'
                });
        }
    });

    app.listen(port, hostname);
}
start().catch(console.error);
