import config from '../config';
import * as database from './database';
import express from 'express';
import Cors from 'cors';
import { ClientError } from './errors';
import { jsonValidate, Optional, parseIntStrict } from './validation';
import { encrypt, getSalt, hashPassword } from './crypto';
import { route, authenticate, checkPermissions } from './util';

async function start() {
    //initialize the database
    if(config.database.autoInit)
        await database.init();

    let {hostname, port} = config.server;

    //create our Express app
    const app = express();
    //create a handler for CORS
    const cors = Cors({
        origin: function(origin, callback) {
            callback(null, true);
        },
        credentials: true
    });
    //setup our artificial delay (if configured)
    if(config.server.artificialDelay > 0){
        app.use((req, res, next) => {
            setTimeout(next, config.server.artificialDelay);
        });
    }
    //handle CORS requests
    app.use(cors);
    let jsonMiddleware = express.json({ strict: false });
    //parse JSON bodies
    app.use((req, res, next) => {
        let type = req.get('content-type');
        if(type != null && type.toLowerCase() === 'application/json')
            jsonMiddleware(req, res, next);
        else
            next();
    });
    //disable caching responses
    app.use((req, res, next) => {
        res.set('Cache-Control', 'no-cache');
        next();
    });

    //reply to all options requests
    app.options('*', cors);

    //region user

    //creates a new user
    app.post('/users', route(async (req, res, db) => {
        let body = req.body;
        //this is an example of how to specify the structure of a body
        //  all entries are required unless wrapped in an optional (like firstName and lastName)
        //  strings specify that the type should be a string (the value of the string is what's used in the response to an invalid body)
        body = jsonValidate(body, {
            firstName: new Optional('John'),
            lastName: new Optional('Doe'),
            username: 'johndoe',
            password: 'secret'
        });
        //create a new salt for our user
        let salt = await getSalt();
        //hash their password with the salt
        let hash = await hashPassword(body.password, salt);
        //update the body
        body.password = hash;
        body.salt = salt;
        //insert the user into the database
        let results;
        try{
            [results] = await db.query(
                `INSERT INTO todo.users SET ?`,
                [body]
            );
        }catch(err){
            //if there is a DUP_ENTRY error, the username is taken, so report to user
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
        //also log in the new user
        let userId = `${results.insertId}`;
        let expireTime = new Date(Date.now() + config.tokenLifetime);
        //insert the new session into the database
        [results] = await db.query(
            `INSERT INTO todo.sessions(userId, expirationDate) VALUES (?, ?)`,
            [userId, expireTime]
        );
        let sessionId = `${results.insertId}`;
        let token = await encrypt({sessionId});
        return {
            status: 201, //201 CREATED
            userId,
            token,
            expireTime
        };
    }));
    //gets the user's information
    app.get('/users', route(async (req, res, db) => {
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
    //updates the user's information
    app.put('/users', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let body = req.body;
        body = jsonValidate(body, {
            firstName: new Optional('John'),
            lastName: new Optional('Doe'),
            password: new Optional('secret')
        });
        //if the request is empty, do nothing
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
    //deletes the user
    app.delete('/users', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let [results] = await db.query(
            `DELETE FROM todo.users WHERE id = ?`,
            [userId]
        );
        if(results.affectedRows === 0)
            throw new Error('Unexpected missing user');
    }));
    //checks if the username is taken
    app.get('/users/name-taken', route(async (req, res, db) => {
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

    //creates a new session
    app.post('/users/login', route(async (req, res, db) => {
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
    //logs out an existing session
    app.post('/users/logout', route(async (req, res, db) => {
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

    //gets the user's lists
    app.get('/lists', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let [results] = await db.query(
            `SELECT id, name FROM todo.lists WHERE id in (SELECT listId FROM todo.permissions WHERE IF(? IS NOT NULL, userId = ?, userId IS NULL))`,
            [userId, userId]
        );
        return {lists: results};
    }));
    //creates a new list
    app.post('/lists', route(async (req, res, db) => {
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
    //gets the info for a list
    app.get('/lists/:listId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        listId = parseIntStrict(listId);
        if(isNaN(listId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //update the info for a list
    app.put('/lists/:listId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        listId = parseIntStrict(listId);
        if(isNaN(listId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //deletes a list (and it's items)
    app.delete('/lists/:listId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        listId = parseIntStrict(listId);
        if(isNaN(listId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
        await checkPermissions(req, db, userId, listId, 'owner');
        let [results] = await db.query(
            `DELETE FROM todo.lists WHERE id = ?`,
            [listId]
        );
        if(results.affectedRows === 0)
            throw new Error('Unexpected missing list');
    }));

    //region list users

    //gets the users which can access a list
    app.get('/lists/:listId/users', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        listId = parseIntStrict(listId);
        if(isNaN(listId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //gets the access level for a user on a list
    app.get('/lists/:listId/users/:userId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, userId: targetUserId} = req.params;
        listId = parseIntStrict(listId);
        targetUserId = parseIntStrict(targetUserId);
        if(isNaN(listId) || isNaN(targetUserId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT role FROM todo.permissions WHERE listId = ? AND userId = ?`,
            [listId, targetUserId]
        );
        let user = results[0] || {};
        return {role: user.role};
    }));
    //sets the access level for a user on a list
    app.put('/lists/:listId/users/:userId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db);
        let {listId, userId: targetUserId} = req.params;
        listId = parseIntStrict(listId);
        targetUserId = parseIntStrict(targetUserId);
        if(isNaN(listId) || isNaN(targetUserId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //deletes a user's access to a list
    app.delete('/lists/:listId/users/:userId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, userId: targetUserId} = req.params;
        listId = parseIntStrict(listId);
        targetUserId = parseIntStrict(targetUserId);
        if(isNaN(listId) || isNaN(targetUserId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
        await checkPermissions(req, db, userId, listId, 'owner');
        await db.query(
            `DELETE FROM todo.permissions WHERE userId = ? AND listId = ?`,
            [targetUserId, listId]
        );
    }));

    //endregion

    //region list items

    //gets the items in a list
    app.get('/lists/:listId/items', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        listId = parseIntStrict(listId);
        if(isNaN(listId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
        await checkPermissions(req, db, userId, listId, 'read');
        let [results] = await db.query(
            `SELECT id, name, description, state FROM todo.items WHERE listId = ? ORDER BY id ASC`,
            [listId]
        );
        return {items: results};
    }));
    //adds a new item to a list
    app.post('/lists/:listId/items', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId} = req.params;
        listId = parseIntStrict(listId);
        if(isNaN(listId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //gets the info for an item in a list
    app.get('/lists/:listId/items/:itemId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, itemId} = req.params;
        listId = parseIntStrict(listId);
        itemId = parseIntStrict(itemId);
        if(isNaN(listId) || isNaN(itemId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //updates the info for an item in a list
    app.put('/lists/:listId/items/:itemId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, itemId} = req.params;
        listId = parseIntStrict(listId);
        itemId = parseIntStrict(itemId);
        if(isNaN(listId) || isNaN(itemId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
    //deletes an item
    app.delete('/lists/:listId/items/:itemId', route(async (req, res, db) => {
        let {userId} = await authenticate(req, db, false);
        let {listId, itemId} = req.params;
        listId = parseIntStrict(listId);
        itemId = parseIntStrict(itemId);
        if(isNaN(listId) || isNaN(itemId)){
            throw new ClientError({
                code: 'invalid-route-param',
                message: `Invalid route parameter. A valid number is required.`
            });
        }
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
        //client errors are "expected" so don't print any debug info to the console
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

    //start listening
    app.listen(port, hostname, () => {
        console.log(`The server is running at http://${hostname}:${port}`);
    });
}
//the the server immediately
start().catch(console.error);
