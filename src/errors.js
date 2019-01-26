/**
 * An error that represents a failure of the user (as opposed to an internal issue)
 */
export class ClientError {
    constructor({status = 400, code, message, data=undefined, headers={}}){
        this.status = status;
        this.code = code;
        this.message = message;
        this.data = data;
        this.headers = headers;
    }
}