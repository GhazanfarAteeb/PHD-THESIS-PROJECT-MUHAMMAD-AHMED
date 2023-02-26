import os
from sqlite3 import Cursor

import solcx
from web3 import Web3
import hashlib
from solcx import set_solc_version, compile_source
from flask import Flask, request, redirect, render_template
import sqlite3

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
            USERNAME TEXT NOT NULL,
            PASSWORD TEXT NOT NULL,
            PRIVATE_KEY TEXT NOT NULL,
            ACCOUNT_ADDRESS TEXT NOT NULL,
            CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP
         );
        
    CREATE TABLE IF NOT EXISTS FILE_UPLOAD(
            ID  INTEGER PRIMARY KEY AUTOINCREMENT,
            FILE_NAME TEXT NOT NULL,
            TRANSACTION_HASH TEXT NOT NULL,
            FILE_BYTES TEXT NOT NULL,
            FILE_HASH TEXT NOT NULL,
            UPLOADED_BY INT NOT NULL,
            CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UPLOADED_BY) REFERENCES USERS(ID)
        );
    '''
    conn.executescript(query)
    return conn


# Compile the contract


@app.route("/register", methods=["POST"])
def register():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE USERNAME=? AND PASSWORD=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() >= 1:
        return "already exist", 200
    else:
        compile_solidity_login_signup_contract()
        conn.execute("INSERT INTO users (USERNAME, PASSWORD, PRIVATE_KEY, ACCOUNT_ADDRESS) VALUES (?, ?, ?, ?)",
                     (request.form["username"],
                      request.form["password"],
                      request.form["private_key"],
                      request.form["account_address"])
                     )
        global login_signup_contract_code, login_signup_contract
        login_signup_contract = compile_source(login_signup_contract_code)
        login_signup_interface = login_signup_contract['<stdin>:LoginSignup']
        login_signup_gas_estimate = w3.eth.estimateGas({'data': login_signup_interface['bin']})
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
        record = records[0]
        compile_solidity_login_signup_contract()
        global login_signup_contract_code, login_signup_contract
        login_signup_contract = compile_source(login_signup_contract_code)
        login_signup_interface = login_signup_contract['<stdin>:LoginSignup']
        login_signup_gas_estimate = w3.eth.estimateGas({'data': login_signup_interface['bin']})
        login_signup_deploy_tx = {
            'from': record[4],
            'data': login_signup_interface['bin'],
            'gas': login_signup_gas_estimate,
            'gasPrice': w3.toWei('1', 'gwei'),
            'nonce': w3.eth.getTransactionCount(record[4])
        }
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_deploy_tx,
                                                                private_key=record[3])
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)
        login_signup_contract_address = login_signup_tx_receipt['contractAddress']
        login_signup_contract_2 = w3.eth.contract(address=login_signup_contract_address,
                                                  abi=login_signup_interface['abi'])

        login_signup_nonce = w3.eth.getTransactionCount(record[4])
        login_signup_tx = login_signup_contract_2.functions.login(record[1], record[2]).buildTransaction({
            'gas': 100000,
            'gasPrice': w3.toWei('0.00000001', 'ether'),
            'nonce': login_signup_nonce
        })
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_tx,
                                                                private_key=record[3])
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)
        return "good to go"
    else:
        return "issue occurred"


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        filename = secure_filename(uploaded_file.filename)
        # ADDING BLOCKCHAIN TRANSACTION AND SQLITE DATABASE RECORD FOR FILE UPLOAD
        # compiled_file_upload_contract = compile_source(file_upload_contract_code)
        uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return {'message': 'File successfully uploaded'}, 201


# # Get the contract interface
# file_upload_interface = compiled_file_upload_contract['<stdin>:FileUpload']
# login_signup_interface = login_signup_contract['<stdin>:LoginSignup']
# # Estimate gas needed for the deployment
# file_upload_gas_estimate = w3.eth.estimateGas({'data': file_upload_interface['bin']})
# login_signup_gas_estimate = w3.eth.estimateGas({'data': login_signup_interface['bin']})
#
# # Set the transaction parameters for deployment
# deploy_file_upload_tx = {
#     'from': w3.eth.accounts[1],
#     'data': file_upload_interface['bin'],
#     'gas': file_upload_gas_estimate,
#     'gasPrice': w3.toWei('1', 'gwei'),
#     'nonce': w3.eth.getTransactionCount(w3.eth.accounts[1])
# }
# # Sign the deployment transaction
# file_upload_signed_tx = w3.eth.account.signTransaction(deploy_file_upload_tx,
#                                                        private_key="de133548e58538f426498b10b2ca18a450b36fa6d6cae9494306ebd84f65f37e")
#
# # Send the deployment transaction
# file_upload_tx_hash = w3.eth.sendRawTransaction(file_upload_signed_tx.rawTransaction)
# # Wait for the deployment transaction to be mined
# file_upload_tx_receipt = w3.eth.waitForTransactionReceipt(file_upload_tx_hash)
# # Get the contract address
# file_upload_contract_address = file_upload_tx_receipt['contractAddress']
#
# login_signup_deploy_tx = {
#     'from': w3.eth.accounts[1],
#     'data': login_signup_interface['bin'],
#     'gas': login_signup_gas_estimate,
#     'gasPrice': w3.toWei('1', 'gwei'),
#     'nonce': w3.eth.getTransactionCount(w3.eth.accounts[1])
# }
# login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_deploy_tx,
#                                                         private_key="de133548e58538f426498b10b2ca18a450b36fa6d6cae9494306ebd84f65f37e")
# login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
# login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)
# login_signup_contract_address = login_signup_tx_receipt['contractAddress']
# # Create the contract instance
# file_upload_contract = w3.eth.contract(address=file_upload_contract_address, abi=file_upload_interface['abi'])
# login_signup_contract = w3.eth.contract(address=login_signup_contract_address, abi=login_signup_interface['abi'])
# # Open the file to be uploaded
# with open("file.txt", "rb") as file:
#     # Read the file as bytes
#     file_bytes = file.read()
#     # Compute the file hash
#     print(hashlib.sha256(file_bytes).hexdigest())
#     file_hash = hashlib.sha256(file_bytes).digest()
#
# # Get the current nonce of the account
# file_upload_nonce = w3.eth.getTransactionCount(w3.eth.accounts[1])
# # Set the transaction parameters
# file_upload_tx = file_upload_contract.functions.uploadFile(file_bytes).buildTransaction({
#     # 'value': w3.toWei(1, 'gwei'),
#     'gas': 1000000,
#     'gasPrice': w3.toWei('0.00001', 'ether'),
#     'nonce': file_upload_nonce,
# })
#
# # Sign the transaction
# file_upload_signed_tx = w3.eth.account.signTransaction(file_upload_tx,
#                                                        private_key="de133548e58538f426498b10b2ca18a450b36fa6d6cae9494306ebd84f65f37e")
# # Send the transaction
# file_upload_tx_hash = w3.eth.sendRawTransaction(file_upload_signed_tx.rawTransaction)
# # Wait for the transaction to be mined
# file_upload_tx_receipt = w3.eth.waitForTransactionReceipt(file_upload_tx_hash)
#
# username = "ghazanfar.ateeb9125@gmail.com"
# password = "12345678"
# login_signup_nonce = w3.eth.getTransactionCount(w3.eth.accounts[1])
# login_signup_tx = login_signup_contract.functions.signup(username, password).buildTransaction({
#     'gas': 100000,
#     'gasPrice': w3.toWei('0.000001', 'ether'),
#     'nonce': login_signup_nonce
# })
# login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_tx,
#                                                         private_key="de133548e58538f426498b10b2ca18a450b36fa6d6cae9494306ebd84f65f37e")
# login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
# login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)
# print(f"FILE_UPLOAD_HASH: {file_upload_tx_receipt}")
# print(f"LOGIN_SIGNUP_HASH: {login_signup_tx_receipt}")
#
# if login_signup_tx_receipt['status'] == 1:
#     print('Login/signup Successful')
# else:
#     print("something went wrong")
#
# # Check the transaction status
# if file_upload_tx_receipt['status'] == 1:
#     print("File uploaded successfully with hash:", file_hash)
# else:
#     print("Transaction failed.")

app.config['UPLOAD_FOLDER'] = 'uploads/'
app.run()
