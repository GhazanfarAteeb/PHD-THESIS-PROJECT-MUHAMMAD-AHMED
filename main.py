import hashlib
import os
import sqlite3
import time

import hexbytes
import solcx
from flask import Flask, request, jsonify
from solcx import set_solc_version, compile_source
from web3 import Web3
from werkzeug.utils import secure_filename

app = Flask(__name__)
w3 = None
file_upload_contract_code = None
login_signup_contract_code = None
login_signup_contract = None


def compile_solidity_login_signup_contract():
    # Set the Solidity compiler version
    solcx.install_solc('0.8.0')
    set_solc_version("0.8.0")

    with open("contracts/LoginSignup.sol", "r") as login_sign_file:
        global login_signup_contract_code
        login_signup_contract_code = login_sign_file.read()


def compile_solidity_file_upload_contract():
    solcx.install_solc('0.8.0')
    set_solc_version("0.8.0")

    with open("contracts/FileUpload.sol", "r") as contract_file:
        global file_upload_contract_code
        file_upload_contract_code = contract_file.read()


def connect_db():
    conn = sqlite3.connect("users.db")
    global w3
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
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
        compile_solidity_login_signup_contract()
        global login_signup_contract_code, login_signup_contract
        login_signup_contract = compile_source(login_signup_contract_code)
        login_signup_interface = login_signup_contract['<stdin>:LoginSignup']

        # creating contract deployment transaction
        login_signup_deploy_tx = {
            'from': request.form['account_address'],
            'data': login_signup_interface['bin'],
            'gas': w3.eth.estimateGas({'data': login_signup_interface['bin']}),  # estimating the gas
            'gasPrice': w3.toWei('1', 'gwei'),
            'nonce': w3.eth.getTransactionCount(request.form['account_address'])
            # checking the transaction count of the user
        }
        # signing the transaction
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_deploy_tx,
                                                                private_key=request.form['private_key'])
        # sending the raw transaction
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        # waiting for the receipt of the transaction
        login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)

        # using the compiled contract's abi and the created contract address the contract call will run
        # the signup method to mine the user signup block
        login_signup_contract_2 = w3.eth.contract(address=login_signup_tx_receipt['contractAddress'],
                                                  abi=login_signup_interface['abi'])

        # creating the transaction for signup function of the smart contract
        login_signup_tx = login_signup_contract_2.functions \
            .signup(request.form['username'], request.form['password']).buildTransaction({
            'gas': 100000,
            'gasPrice': w3.toWei('0.00000001', 'ether'),
            'nonce': w3.eth.getTransactionCount(request.form['account_address'])
        })
        # signing up the transaction
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_tx,
                                                                private_key=request.form['private_key'])
        # sending the transaction
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        # waiting for the receipt
        login_signup_tx_receipt_2 = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)
        # adding the user to the database
        conn.execute(
            '''INSERT INTO users (USERNAME, PASSWORD, PRIVATE_KEY, ACCOUNT_ADDRESS, CONTRACT_ADDRESS) 
            VALUES (?, ?, ?, ?, ?)''',
            (request.form["username"],
             request.form["password"],
             request.form["private_key"],
             request.form["account_address"],
             login_signup_tx_receipt['contractAddress'])
        )
    conn.commit()
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

        # compiling the contract for its execution
        compile_solidity_login_signup_contract()
        global login_signup_contract_code, login_signup_contract
        login_signup_contract = compile_source(login_signup_contract_code)
        login_signup_interface = login_signup_contract['<stdin>:LoginSignup']
        # noting the compiling time of the contract
        contract_compile_time = time.time()

        # getting the contract address from the database
        login_signup_contract_address = record[4]
        login_signup_contract_2 = w3.eth.contract(address=login_signup_contract_address,
                                                  abi=login_signup_interface['abi'])

        # building the transaction for the login process
        login_signup_tx = login_signup_contract_2.functions.login(record[1], record[2]).buildTransaction({
            'gas': 100000,
            'gasPrice': w3.toWei('0.00000001', 'ether'),
            'nonce': w3.eth.getTransactionCount(record[4])
        })
        # signing the blockchain transaction
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_tx, private_key=record[3])
        # sending the blockchain transaction
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        # wait for getting the transaction receipt
        login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)
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


@app.route('/upload', methods=['POST'])
def upload_file():
    print(request.form)
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
            start_time = time.time()
            # getting the database record
            record = records[0]
            filename = secure_filename(uploaded_file.filename)
            # ADDING BLOCKCHAIN TRANSACTION AND SQLITE DATABASE RECORD FOR FILE UPLOAD
            compile_solidity_file_upload_contract()
            global file_upload_contract_code
            compiled_file_upload_contract = compile_source(file_upload_contract_code)
            uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_upload_interface = compiled_file_upload_contract['<stdin>:FileUpload']
            file_upload_gas_estimate = w3.eth.estimateGas({'data': file_upload_interface['bin']})
            deploy_file_upload_tx = {
                'from': record[4],
                'data': file_upload_interface['bin'],
                'gas': file_upload_gas_estimate,
                'gasPrice': w3.toWei('1', 'gwei'),
                'nonce': w3.eth.getTransactionCount(record[4])
            }
            file_upload_signed_tx = w3.eth.account.signTransaction(deploy_file_upload_tx, private_key=record[3])
            file_upload_tx_hash = w3.eth.sendRawTransaction(file_upload_signed_tx.rawTransaction)
            file_upload_tx_receipt = w3.eth.waitForTransactionReceipt(file_upload_tx_hash)
            print(file_upload_tx_receipt['contractAddress'])
            with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb") as file:
                # Read the file as bytes
                file_bytes = file.read()
                print(file_bytes)
                file_upload_contract_2 = w3.eth.contract(address=file_upload_tx_receipt['contractAddress'],
                                                         abi=file_upload_interface['abi'])
                details = file_upload_contract_2.functions.uploadFile(file_bytes).transact({'from': record[4]})
        return {'message': 'File successfully uploaded'}, 201


@app.route('/check', methods=['POST'])
def check_file():
    compile_solidity_file_upload_contract()
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM FILE_UPLOAD INNER JOIN USERS U on U.USERNAME = FILE_UPLOAD.UPLOADED_BY "
                   "WHERE FILE_UPLOAD.UPLOADED_BY =? ",
                   (request.form['username'],))
    records = cursor.fetchall()

    if records.__len__() == 1:
        # Check if file hash was provided
        # if 'hash' not in request.form:
        #     return jsonify({'error': 'File hash not found'})

        # Retrieve file hash from request
        # file_hash = request.form['hash']
        record = records[0]
        # Check if file exists in FileUpload contract
        global file_upload_contract_code
        compiled_file_upload_contract = compile_source(file_upload_contract_code)
        file_upload_interface = compiled_file_upload_contract['<stdin>:FileUpload']
        file_upload_contract_2 = w3.eth.contract(address=record[3],
                                                 abi=file_upload_interface['abi'])
        # print(file_upload_interface['abi'])

        with open(os.path.join(app.config['UPLOAD_FOLDER'], "HDFC_Success_2.json"), "rb") as file:
            # Read the file as bytes
            file_bytes = file.read()
        # print(
        #
        # )
        print(file_bytes)
        stored = file_upload_contract_2.functions.getHash(file_bytes).transact({'from': record[12]})
        info = file_upload_contract_2.functions.checkFile(stored).call()
        print()
        if not info:
            return jsonify({'error': 'File not found in blockchain'})

        # Retrieve file hash from FileHash contract
        # stored_hash = file_upload_contract_2.functions.getHash().call({'from': record[12]})
        # Compare file hashes
        print(info)
        # if file_hash != stored_hash:
        #     return jsonify({'error': 'File hash does not match stored hash'})
        return 'abc', 201

    else:
        return 'lol', 200
        # return jsonify({'success': 'File integrity verified', 'owner': owner, 'timestamp': timestamp})


app.config['UPLOAD_FOLDER'] = 'uploads/'
app.run()
