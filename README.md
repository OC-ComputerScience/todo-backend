###Todo Backend

This project is the example backend for the Todo App, implemented with Express.

#### Prerequisites
##### Node v10

* Windows: 
    https://nodejs.org/en/download/

* Ubuntu:
    ```bash
    curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
    sudo apt install -y nodejs
    ```

#### Setup

1. First, clone to repo to make a local copy of it.
    ```bash
    git clone https://gitlab.com/oc-internet-apps/todo-backend.git
    ```
2. Update the database password in `config.js`.
3. Install dependencies
    ```bash
    npm install
    ```
4. Build source code
    ```bash
    npm run build
    ```
5. Run server
    ```bash
    npm run start
    ```
    The server will continue running in the current console window, so leave it open.