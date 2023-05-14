import sqlite3
import time

import hexbytes
from flask import Flask, request
from web3 import Web3

from FileContract import FileContract
from LoginSignupContract import LoginSignupContract

app = Flask(__name__)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))

file_contract = FileContract()
login_signup_contract = LoginSignupContract()

app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['PERMANENT_SESSION_LIFETIME'] = 6000


def connect_db():
    conn = sqlite3.connect("users.db")
    query = '''
    CREATE TABLE IF NOT EXISTS USERS (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            USERNAME TEXT UNIQUE NOT NULL,
            PASSWORD TEXT NOT NULL,
            PRIVATE_KEY TEXT NOT NULL,
            ACCOUNT_ADDRESS TEXT NOT NULL,
            CONTRACT_ADDRESS TEXT NOT NULL,
            CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP
         );

    CREATE TABLE IF NOT EXISTS FILE_UPLOAD(
            ID  INTEGER PRIMARY KEY AUTOINCREMENT,
            FILE_NAME TEXT NOT NULL,
            TRANSACTION_HASH TEXT NOT NULL,
            FILE_CONTRACT TEXT NOT NULL,
            FILE_BYTES TEXT NOT NULL,
            FILE_HASH TEXT NOT NULL,
            UPLOADED_BY INT NOT NULL,
            CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UPLOADED_BY) REFERENCES USERS(USERNAME)
        );
    '''
    conn.executescript(query)
    return conn


# Compile the contract


@app.route("/register", methods=["POST"])
def register():
    conn = connect_db()
    cursor = conn.cursor()
    # checking if the user already exists in the database or not
    cursor.execute("SELECT * FROM users WHERE USERNAME=? AND PASSWORD=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() >= 1:
        return "already exist", 200
    else:
        # if the user does not exist then the contract will be created on the user registration and the signup method
        # will be called to add the user to the blockchain network

        # compiling the blockchain contract

        receipt, receipt2 = login_signup_contract.register(w3, request.form['account_address'],
                                                                   request.form["private_key"],
                                                                   request.form["username"], request.form["password"])
        # adding the user to the database
        conn.execute(
            '''INSERT INTO users (USERNAME, PASSWORD, PRIVATE_KEY, ACCOUNT_ADDRESS, CONTRACT_ADDRESS)
            VALUES (?, ?, ?, ?, ?)''',
            (request.form["username"],
             request.form["password"],
             request.form["private_key"],
             request.form["account_address"],
             receipt['contractAddress'])
        )
    # conn.commit()
    return "sent", 200

@app.route("/register_via_ibs", methods=["POST"])
def registerViaIBS():
    conn = connect_db()
    cursor = conn.cursor()
    # checking if the user already exists in the database or not
    cursor.execute("SELECT * FROM users WHERE USERNAME=? AND PASSWORD=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() >= 1:
        return "already exist", 200
    else:
        # if the user does not exist then the contract will be created on the user registration and the signup method
        # will be called to add the user to the blockchain network

        # compiling the blockchain contract

        receipt, receipt2 = login_signup_contract.register(w3, request.form['account_address'],
                                                                   request.form["private_key"],
                                                                   request.form["username"], request.form["password"])
        # adding the user to the database
        conn.execute(
            '''INSERT INTO users (USERNAME, PASSWORD, PRIVATE_KEY, ACCOUNT_ADDRESS, CONTRACT_ADDRESS)
            VALUES (?, ?, ?, ?, ?)''',
            (request.form["username"],
             request.form["password"],
             request.form["private_key"],
             request.form["account_address"],
             receipt['contractAddress'])
        )
    # conn.commit()
    return "sent", 200

@app.route("/login", methods=["POST"])
def login():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() == 1:
        # noting the start time for the execution
        start_time = time.time()
        # getting the database record
        record = records[0]
        # noting the compiling time of the contract
        contract_compile_time = time.time()

        # getting the contract address from the database
        login_signup_tx_receipt = login_signup_contract.login(record=record, w3=w3)
        # noting the time after the transaction is completed
        contract_transaction_time = time.time()
        # getting the transaction hash for the mined block
        tx_hash = hexbytes.HexBytes(login_signup_tx_receipt['transactionHash'])
        # response to return
        response = {
            'id': record[0],
            'username': record[1],
            'account_address': record[4],
            'contract_address': record[5],
            'block_number': login_signup_tx_receipt['blockNumber'],
            'from': login_signup_tx_receipt['from'],
            'to': login_signup_tx_receipt['to'],
            'gas_used': login_signup_tx_receipt['gasUsed'],
            'cumulative_gas_used': login_signup_tx_receipt['cumulativeGasUsed'],
            'transaction_hash': tx_hash.hex().__str__(),
            'start_time': start_time * 1000,
            'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
            'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
        }
        # returning the response
        return response, 200
    else:
        return "issue occurred"


@app.route("/login_via_ibs", methods=["POST"])
def loginViaIBS():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() == 1:
        # noting the start time for the execution
        start_time = time.time()
        # getting the database record
        record = records[0]
        # noting the compiling time of the contract
        contract_compile_time = time.time()

        # getting the contract address from the database
        login_signup_tx_receipt = login_signup_contract.loginWithDBDH(record=record, w3=w3)
        # noting the time after the transaction is completed
        contract_transaction_time = time.time()
        # getting the transaction hash for the mined block
        tx_hash = hexbytes.HexBytes(login_signup_tx_receipt['transactionHash'])
        # response to return
        response = {
            'id': record[0],
            'username': record[1],
            'account_address': record[4],
            'contract_address': record[5],
            'block_number': login_signup_tx_receipt['blockNumber'],
            'from': login_signup_tx_receipt['from'],
            'to': login_signup_tx_receipt['to'],
            'gas_used': login_signup_tx_receipt['gasUsed'],
            'cumulative_gas_used': login_signup_tx_receipt['cumulativeGasUsed'],
            'transaction_hash': tx_hash.hex().__str__(),
            'start_time': start_time * 1000,
            'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
            'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
        }
        # returning the response
        return response, 200
    else:
        return "issue occurred"


@app.route('/upload_via_shredding', methods=['POST'])
def upload_file_via_shredding():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ", (request.form['username'],))
        records = cursor.fetchall()
        if records.__len__() == 1:
            # getting the database record
            record = records[0]

            file_contract.upload_file_via_shredding(uploaded_file=uploaded_file, w3=w3, record=record,
                                                    upload_folder=str(app.config['UPLOAD_FOLDER']))
    return {'message': 'File successfully uploaded'}, 201


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ",
                       (request.form['username'],))
        records = cursor.fetchall()
        if records.__len__() == 1:
            # noting the start time for the execution
            # getting the database record
            record = records[0]
            file_contract.upload_file_simple(uploaded_file=uploaded_file, w3=w3, record=record,
                                             upload_folder=app.config['UPLOAD_FOLDER'])
            # ADDING BLOCKCHAIN TRANSACTION AND SQLITE DATABASE RECORD FOR FILE UPLOAD

        return {'message': 'File successfully uploaded'}, 201


@app.route('/check', methods=['POST'])
def check_file():
    # Compile the smart contract

    # Connect to the database and retrieve the file record
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM FILE_UPLOAD INNER JOIN USERS U on U.USERNAME = FILE_UPLOAD.UPLOADED_BY "
                   "WHERE FILE_UPLOAD.UPLOADED_BY = ?", (request.form['username'],))
    records = cursor.fetchall()

    if len(records) != 1:
        return {'error': 'File not found'}

    record = records[0]
    file_address = record[3]
    file_owner = record[12]

    # Connect to the smart contract and retrieve the file hash

    if file_contract.check_file(w3=w3, record=record, file_address=file_address, file_owner=file_owner,
                                upload_folder=app.config['UPLOAD_FOLDER']):
        return {'error': 'File hash does not match stored hash'}

    return {'success': 'File integrity verified', 'owner': record[9], 'timestamp': record[10]}


app.run(debug=True)
