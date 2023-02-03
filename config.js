module.exports = {
  server: {
    //the server info for the api
    //  you should not need to change this
    hostname: "localhost",
    port: 3001,
    //the secret key for the server
    //  ordinarily we would not want to check this into git, but we don't care for this example
    secretKey: Buffer.from(
      "xT1tdO3CfMH01pjxC+guN1LWSt2nKvr5td6KUpw7Czg=",
      "base64"
    ),
    //an artificial delay (in ms) to add to all responses
    //  useful for testing loading icons and such with a local server
    artificialDelay: 0
  },
  database: {
    //the database server info
    //  you should not need to change this unless your server is on another machine
    hostname: "localhost",
    port: 3306,
    //the authentication info for the database
    username: "root",
    password: "", //!!!CHANGE ME!!!
    //the database in which to store the data
    database: "todo",
    //true to automatically setup the DB tables
    autoInit: true
  },
  //the lifetime of an auth token
  tokenLifetime: 24 * 60 * 60 * 1000
};
