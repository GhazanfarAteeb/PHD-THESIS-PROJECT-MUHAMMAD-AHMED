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
            UPLOADED_BY TEXT NOT NULL,
            CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UPLOADED_BY) REFERENCES USERS(USERNAME)
        );
    '''
    conn.executescript(query)
    return conn


def insert_file_record(file_name, transaction_hash, file_contract, file_bytes, file_hash, uploaded_by):
    conn = connect_db()
    cursor = conn.cursor()
    # print('HERE')
    # Check if the user exists
    cursor.execute("SELECT * FROM USERS WHERE USERNAME=?", (uploaded_by,))
    record = cursor.fetchone()
    if not record:
        return {'message': 'User does not exist'}, 404

    # Insert the file record into the database
    conn.execute(
        "INSERT INTO FILE_UPLOAD(FILE_NAME, TRANSACTION_HASH, FILE_CONTRACT, FILE_BYTES, FILE_HASH, UPLOADED_BY)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (file_name, transaction_hash, file_contract, file_bytes, file_hash, uploaded_by))
    conn.commit()


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
        response = ""
        start_time = time.time()
        login_signup_contract.compile_contract()
        contract_compile_time = time.time()
        receipt, receipt2 = login_signup_contract.register(w3, request.form['account_address'],
                                                           request.form["private_key"],
                                                           request.form["username"], request.form["password"])
        contract_transaction_time = time.time()
        conn.execute(
            '''INSERT INTO users (USERNAME, PASSWORD, PRIVATE_KEY, ACCOUNT_ADDRESS, CONTRACT_ADDRESS)
            VALUES (?, ?, ?, ?, ?)''',
            (request.form["username"],
             request.form["password"],
             request.form["private_key"],
             request.form["account_address"],
             receipt['contractAddress'])
        )
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE USERNAME=? AND PASSWORD=?",
                       (request.form['username'], request.form['password']))
        records = cursor.fetchall()
        tx_hash = hexbytes.HexBytes(receipt['transactionHash'])
        tx_hash2 = hexbytes.HexBytes(receipt2['transactionHash'])
        if records.__len__() >= 1:
            record = records[0]
            response = {
                'id': record[0],
                'username': record[1],
                'account_address': record[4],
                'contract_address': record[5],
                'block_number': [
                    receipt['blockNumber'],
                    receipt2['blockNumber']
                ],
                'from': receipt2['from'],
                'to': receipt2['to'],
                'gas_used': [
                    receipt['gasUsed'],
                    receipt2['gasUsed']
                ],
                'cumulative_gas_used': (receipt['cumulativeGasUsed'] + receipt2['cumulativeGasUsed']),
                'transaction_hash': [
                    tx_hash.hex().__str__(),
                    tx_hash2.hex().__str__()
                ],
                'start_time': start_time * 1000,
                'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
                'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
            }
    return response, 200


@app.route("/register_via_ibs", methods=["POST"])
def registerViaIBS():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE USERNAME=? AND PASSWORD=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() >= 1:
        return "already exist", 200
    else:
        response = ""
        start_time = time.time()
        login_signup_contract.compile_contract()
        contract_compile_time = time.time()
        receipt, receipt2 = login_signup_contract.registerWithDBDH(w3, request.form['account_address'],
                                                                   request.form["private_key"],
                                                                   request.form["username"], request.form["password"])
        contract_transaction_time = time.time()
        conn.execute(
            '''INSERT INTO users (USERNAME, PASSWORD, PRIVATE_KEY, ACCOUNT_ADDRESS, CONTRACT_ADDRESS)
            VALUES (?, ?, ?, ?, ?)''',
            (request.form["username"],
             request.form["password"],
             request.form["private_key"],
             request.form["account_address"],
             receipt['contractAddress'])
        )
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE USERNAME=? AND PASSWORD=?",
                       (request.form['username'], request.form['password']))
        records = cursor.fetchall()
        tx_hash = hexbytes.HexBytes(receipt['transactionHash'])
        tx_hash2 = hexbytes.HexBytes(receipt2['transactionHash'])
        if records.__len__() >= 1:
            record = records[0]
            response = {
                'id': record[0],
                'username': record[1],
                'account_address': record[4],
                'contract_address': record[5],
                'block_number': [
                    receipt['blockNumber'],
                    receipt2['blockNumber']
                ],
                'from': receipt2['from'],
                'to': receipt2['to'],
                'gas_used': [
                    receipt['gasUsed'],
                    receipt2['gasUsed']
                ],
                'cumulative_gas_used': (receipt['cumulativeGasUsed'] + receipt2['cumulativeGasUsed']),
                'transaction_hash': [
                    tx_hash.hex().__str__(),
                    tx_hash2.hex().__str__()
                ],
                'start_time': start_time * 1000,
                'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
                'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
            }
    return response, 200


@app.route("/login", methods=["POST"])
def login():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                   (request.form['username'], request.form['password']))
    records = cursor.fetchall()
    if records.__len__() == 1:

        start_time = time.time()
        record = records[0]
        login_signup_contract.compile_contract()
        contract_compile_time = time.time()
        login_signup_tx_receipt = login_signup_contract.login(record=record, w3=w3)
        contract_transaction_time = time.time()
        tx_hash = hexbytes.HexBytes(login_signup_tx_receipt['transactionHash'])
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
        start_time = time.time()
        record = records[0]
        contract_compile_time = time.time()
        login_signup_tx_receipt = login_signup_contract.loginWithDBDH(record=record, w3=w3)
        contract_transaction_time = time.time()
        tx_hash = hexbytes.HexBytes(login_signup_tx_receipt['transactionHash'])
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
        return response, 200
    else:
        return "issue occurred"


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        response = ""
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ",
                       (request.form['username'],))
        records = cursor.fetchall()
        if records.__len__() == 1:
            start_time = time.time()
            file_contract.compile_contract()
            record = records[0]
            contract_compile_time = time.time()
            details, receipt, file_bytes = file_contract.upload_file_simple(uploaded_file=uploaded_file, w3=w3,
                                                                            record=record,
                                                                            upload_folder=app.config['UPLOAD_FOLDER'])

            # print(file_bytes)
            tx_hash = hexbytes.HexBytes(receipt['transactionHash'])
            # file_name, transaction_hash, file_contract, file_bytes, file_hash, uploaded_by
            insert_file_record(uploaded_file.filename, tx_hash, receipt['contractAddress'], file_bytes, details,
                               record[1])
            contract_transaction_time = time.time()
            cursor.execute("SELECT * FROM FILE_UPLOAD WHERE FILE_CONTRACT=?", (receipt['contractAddress'],))
            recs = cursor.fetchall()
            rec = recs[0]
            response = {
                'id': rec[0],
                'uid': record[0],
                'account_address': record[4],
                'contract_address': receipt['contractAddress'],
                'block_number': receipt['blockNumber'],
                'from': receipt['from'],
                'gas_used': receipt['gasUsed'],
                'cumulative_gas_used': receipt['cumulativeGasUsed'],
                'transaction_hash': tx_hash.hex().__str__(),
                'start_time': start_time * 1000,
                'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
                'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
            }
        return response, 200


@app.route('/upload_via_shredding', methods=['POST'])
def upload_file_via_shredding():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        start_time = time.time()
        response = ""
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ", (request.form['username'],))
        records = cursor.fetchall()
        if records.__len__() == 1:
            record = records[0]
            file_contract.compile_contract()
            contract_compile_time = time.time()
            details, receipt = file_contract.upload_file_via_shredding(uploaded_file=uploaded_file, w3=w3,
                                                                       record=record,
                                                                       upload_folder=str(app.config['UPLOAD_FOLDER']))
            tx_hash = hexbytes.HexBytes(receipt['transactionHash'])
            insert_file_record(uploaded_file.filename, tx_hash, receipt['contractAddress'], details,
                               receipt['blockHash'], record[1])
            contract_transaction_time = time.time()
            cursor.execute("SELECT * FROM FILE_UPLOAD WHERE FILE_CONTRACT=?", (receipt['contractAddress'],))
            recs = cursor.fetchall()
            rec = recs[0]
            response = {
                'id': rec[0],
                'uid': record[0],
                'account_address': record[4],
                'contract_address': receipt['contractAddress'],
                'block_number': receipt['blockNumber'],
                'from': receipt['from'],
                'gas_used': receipt['gasUsed'],
                'cumulative_gas_used': receipt['cumulativeGasUsed'],
                'transaction_hash': tx_hash.hex().__str__(),
                'start_time': start_time * 1000,
                'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
                'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
            }
        return response, 200


@app.route('/upload_via_hvt', methods=['POST'])
def upload_file_via_hvt():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        response = ""
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ",
                       (request.form['username'],))
        records = cursor.fetchall()
        if records.__len__() == 1:
            start_time = time.time()
            record = records[0]
            file_contract.compile_contract()
            contract_compile_time = time.time()
            details, receipt = file_contract.upload_file_with_HVT(
                uploaded_file=uploaded_file, w3=w3, record=record,
                upload_folder=app.config['UPLOAD_FOLDER']
            )
            tx_hash = hexbytes.HexBytes(receipt['transactionHash'])
            insert_file_record(uploaded_file.filename, tx_hash, receipt['contractAddress'], details,
                               receipt['blockHash'], record[1])
            contract_transaction_time = time.time()
            cursor.execute("SELECT * FROM FILE_UPLOAD WHERE FILE_CONTRACT=?", (receipt['contractAddress'],))
            recs = cursor.fetchall()
            rec = recs[0]
            response = {
                'id': rec[0],
                'uid': record[0],
                'account_address': record[4],
                'contract_address': receipt['contractAddress'],
                'block_number': receipt['blockNumber'],
                'from': receipt['from'],
                'gas_used': receipt['gasUsed'],
                'cumulative_gas_used': receipt['cumulativeGasUsed'],
                'transaction_hash': tx_hash.hex().__str__(),
                'start_time': start_time * 1000,
                'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
                'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
            }
        return response, 200


@app.route('/upload_via_shredding_and_hvt', methods=['POST'])
def upload_file_via_shredding_and_hvt():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    if uploaded_file:
        response = ""
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ",
                       (request.form['username'],))
        records = cursor.fetchall()
        if records.__len__() == 1:
            start_time = time.time()
            record = records[0]
            file_contract.compile_contract()
            contract_compile_time = time.time()
            details, receipt = file_contract.upload_file_via_shredding_and_hvt(
                uploaded_file=uploaded_file, w3=w3,
                record=record,
                upload_folder=app.config['UPLOAD_FOLDER']
            )
            tx_hash = hexbytes.HexBytes(receipt['transactionHash'])
            insert_file_record(uploaded_file.filename, tx_hash, receipt['contractAddress'], details,
                               receipt['blockHash'], record[1])
            contract_transaction_time = time.time()
            cursor.execute("SELECT * FROM FILE_UPLOAD WHERE FILE_CONTRACT=?", (receipt['contractAddress'],))
            recs = cursor.fetchall()
            rec = recs[0]
            response = {
                'id': rec[0],
                'uid': record[0],
                'account_address': record[4],
                'contract_address': receipt['contractAddress'],
                'block_number': receipt['blockNumber'],
                'from': receipt['from'],
                'gas_used': receipt['gasUsed'],
                'cumulative_gas_used': receipt['cumulativeGasUsed'],
                'transaction_hash': tx_hash.hex().__str__(),
                'start_time': start_time * 1000,
                'contract_compiled_time_taken': ((contract_compile_time - start_time) * 1000),
                'contract_transaction_time_taken': ((contract_transaction_time - contract_compile_time) * 1000)
            }
        return response, 200


@app.route('/check', methods=['POST'])
def check_file():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM FILE_UPLOAD INNER JOIN USERS U on U.USERNAME = FILE_UPLOAD.UPLOADED_BY "
                   "WHERE FILE_UPLOAD.UPLOADED_BY = ?", (request.form['username'],))
    records = cursor.fetchall()

    if len(records) < 1:
        return {'error': 'File not found'}

    verified_files = []
    files_verified_response = []
    overall_time_taken = time.time()
    # file_contract.check_file(w3=w3, record=record)
    for record in records:
        verification_start_time = time.time()
        is_verified = file_contract.check_file(w3=w3, record=record) != b''
        if is_verified:
            verified_files.append(record)
        verification_end_time = time.time()
        files_verified_response.append({
            'id': record[0],
            'uid': record[8],
            'username': record[9],
            'verification_start_time': f'{verification_start_time * 1000} ms',
            'verification_end_time': f'{verification_end_time * 1000} ms',
            'time_consumed': f'{(verification_end_time - verification_start_time) * 1000} ms',
            'account_address': record[12],
            'file_contract': record[3],
            'user_contract': record[13],
            'is_file_verified': is_verified
        })
    overall_time_taken = time.time() - overall_time_taken
    if verified_files.__len__() != records.__len__():
        return {
                'message': 'Integrity report of all files',
                'status': 'File hash does not match stored hash',
                'overall_time_taken': f'{overall_time_taken * 1000} ms',
                'data': files_verified_response
         }
    return {
            'message': 'Integrity report of all files',
            'status': 'File integrity verified',
            'overall_time_taken': f'{overall_time_taken * 1000} ms',
            'data': files_verified_response
        }


app.run(debug=True)
