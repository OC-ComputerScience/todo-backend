import crypto from 'crypto';
import config from '../config';
import { ClientError } from './errors';

export const saltSize = 16;
export const keySize = 64;
export const ivSize = 16;
export const tagSize = 16;
const scryptOptions = {
    N: 16384,
    r: 8,
    p: 1
};
const secretKey = config.server.secretKey;

export async function getSalt() {
    return new Promise((fulfill, reject) => {
        crypto.randomBytes(saltSize, (err, salt) => {
            if(err)
                reject(err);
            else
                fulfill(salt);
        });
    });
}

export async function hashPassword(password, salt) {
    return new Promise((fulfill, reject) => {
        crypto.scrypt(password, salt, keySize, scryptOptions, (err, key) => {
            if(err)
                reject(err);
            else
                fulfill(key);
        });
    });
}

export async function encrypt(content) {
    let str = JSON.stringify(content);
    let iv = await crypto.randomBytes(ivSize);
    let cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    let encrypted = Buffer.concat([
        cipher.update(str, 'utf8'),
        cipher.final()
    ]);
    let tag = cipher.getAuthTag();
    if(tag.length !== tagSize)
        throw new Error('Unexpected tag size');
    let buffer = Buffer.concat([iv, tag, encrypted]);
    return buffer.toString('base64');
}

export async function decrypt(token) {
    try{
        let buffer = Buffer.from(token, 'base64');
        let iv = buffer.slice(0, ivSize);
        let tag = buffer.slice(ivSize, ivSize + tagSize);
        let encrypted = buffer.slice(ivSize + tagSize);
        let decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, iv);
        decipher.setAuthTag(tag);
        let str = decipher.update(encrypted, 'binary', 'utf8') + decipher.final('utf8');
        return JSON.parse(str);
    }catch{
        throw new ClientError({
            code: 'invalid-auth',
            message: 'Invalid authentication'
        });
    }
}