import os
import shutil
import sqlite3
import time

import hexbytes
from ecdsa import SigningKey, VerifyingKey
from flask import Flask, request
from web3 import Web3
from werkzeug.utils import secure_filename

from DataStorage import DataStorage
from FileContract import FileContract
from LoginSignupContract import LoginSignupContract

app = Flask(__name__)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))

file_contract = FileContract()
login_signup_contract = LoginSignupContract()
data_storage = DataStorage()

app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['PERMANENT_SESSION_LIFETIME'] = 6000
app.config['FILE_CHUNKS'] = app.config['UPLOAD_FOLDER'] + 'chunks/'
app.config['SIGNED_FILES'] = app.config['UPLOAD_FOLDER'] + 'signed_files/'
app.config['USER_PRIVATE_KEYS'] = 'private_keys/'
app.config['USER_PUBLIC_KEYS'] = 'public_keys/'
app.config['VERIFIABLE_FILES'] = app.config['UPLOAD_FOLDER'] + 'verifiable_files/'
app.config['VERIFIABLE_SIGNED_FILES'] = app.config['UPLOAD_FOLDER'] + 'uploaded_signed_files/'


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
   CREATE TABLE IF NOT EXISTS DATA_STORAGE(
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            FILE_CHUNK_CONTRACT_ADDRESS TEXT NOT NULL,
            CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP,
            UPLOADED_BY TEXT NOT NULL
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
                                                                            upload_folder=app.config['FILE_CHUNKS'])

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


def get_user_into(username):
    conn = connect_db()
    cursor = conn.cursor()
    # Fetch user information from the database based on the provided username
    cursor.execute("SELECT * FROM USERS WHERE USERNAME=? ", (username,))
    records = cursor.fetchall()
    cursor.close()
    return records


def mine_block(w3, record):
    conn = connect_db()
    cursor = conn.cursor()
    receipt = data_storage.create_block(w3, record)
    cursor.execute("INSERT INTO DATA_STORAGE(FILE_CHUNK_CONTRACT_ADDRESS, UPLOADED_BY) VALUES (?,?)",
                   (receipt['contractAddress'], record[1],))
    conn.commit()


def get_user_data_storage_info():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM DATA_STORAGE WHERE UPLOADED_BY=?', (request.form['username'],))
    records2 = cursor.fetchall()
    cursor.close()
    return records2


def make_folder_and_clear_existing(file_chunks_folder_path):
    if not os.path.exists(file_chunks_folder_path):
        os.mkdir(file_chunks_folder_path)
    else:
        shutil.rmtree(file_chunks_folder_path)
        os.mkdir(file_chunks_folder_path)


def create_file_chunks(uploaded_file, chunk_size, filename):
    uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    # Read the file in chunks and store in arrays
    with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb") as file:
        file_bytes = file.read()
        file_bytes_array = [file_bytes[i:i + chunk_size] for i in range(0, len(file_bytes), chunk_size)]
    return file_bytes_array


def write_file_data(file_bytes_array, file_chunks_folder_path, record, record2, sk, filename):
    signed_file_chunks_folder_path = app.config['SIGNED_FILES'] + f'{filename}/'
    if not os.path.exists(signed_file_chunks_folder_path):
        os.mkdir(signed_file_chunks_folder_path)
    else:
        shutil.rmtree(signed_file_chunks_folder_path)
        os.mkdir(signed_file_chunks_folder_path)
    for i in range(0, len(file_bytes_array)):
        # Write file chunk to disk
        with open(f'{file_chunks_folder_path}/{i}.bin', "wb") as f:
            f.write(file_bytes_array[i])

        # Sign the file chunk
        signature = sk.sign(file_bytes_array[i])

        with open(os.path.join(signed_file_chunks_folder_path, f'{i}.bin'), "wb") as file:
            file.write(signature)

        data_storage.store_bytes(w3=w3, contract_address=record2[1], tx_from=record[4], signature=signature)
        data_storage.retrieve_bytes(w3, record, signature, contract_address=record2[1])
        result = data_storage.verify(
            w3=w3, signature=signature, record=record, file_bytes_array=file_bytes_array,
            index=i, contract_address=record2[1], vk=sk.verifying_key
        )

        print(result)


@app.route('/upload_file_chunked', methods=['POST'])
def upload_file_chunked():
    # Check if 'file' is present in the request
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400

    # Get the uploaded file from the request
    uploaded_file = request.files['file']

    # Check if a file was selected for uploading
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400

    if 'chunkSize' not in request.form:
        return {'message': 'No chunk size provided'}, 400

    if uploaded_file:
        response = ""
        records = get_user_into(request.form['username'])

        if len(records) == 1:
            record = records[0]
            records2 = get_user_data_storage_info()
            if len(records2) < 1:
                mine_block(w3, record)
                records2 = get_user_data_storage_info()
            record2 = records2[0]
            # Generate signing and verifying keys
            if os.path.exists(os.path.join(app.config['USER_PRIVATE_KEYS'], f"{record[0]}.pem")):
                private_key_path = os.path.join(app.config['USER_PRIVATE_KEYS'], f"{record[0]}.pem")
            if os.path.exists(os.path.join(app.config['USER_PUBLIC_KEYS'], f"{record[0]}.pem")):
                public_key_path = os.path.join(app.config['USER_PUBLIC_KEYS'], f"{record[0]}.pem")

                with open(private_key_path, "rb") as f:
                    file_bytes = f.read()
                    file_str = file_bytes.decode('utf-8')
                    sk = SigningKey.from_pem(file_str)
                with open(public_key_path, "rb") as f:
                    file_bytes = f.read()
                    file_str = file_bytes.decode('utf-8')
                sk.verifying_key = VerifyingKey.from_pem(file_str)
            else:
                sk = SigningKey.generate()
                with open(os.path.join(app.config['USER_PRIVATE_KEYS'], f'{record[0]}.pem'), "wb") as f:
                    f.write(sk.to_pem())
                with open(os.path.join(app.config['USER_PUBLIC_KEYS'], f'{record[0]}.pem'), "wb") as f:
                    f.write(sk.verifying_key.to_pem())
            chunk_size = int(request.form['chunkSize'])

            filename = secure_filename(uploaded_file.filename)
            file_bytes_array = create_file_chunks(uploaded_file=uploaded_file, chunk_size=chunk_size, filename=filename)
            file_chunks_folder_path = app.config['FILE_CHUNKS'] + f'{filename}/'
            make_folder_and_clear_existing(file_chunks_folder_path=file_chunks_folder_path)

            # Process each file chunk
            write_file_data(
                file_bytes_array=file_bytes_array,
                file_chunks_folder_path=file_chunks_folder_path,
                record=record,
                record2=record2,
                sk=sk,
                filename=filename
            )
        else:
            return {'message': 'USERNAME NOT FOUND'}
        return response, 200


def get_signing_key(record):
    private_key_path = os.path.join(app.config['USER_PRIVATE_KEYS'], f"{record[0]}.pem")
    with open(private_key_path, "r") as f:
        file_bytes = f.read()
        sk = SigningKey.from_pem(file_bytes)
    public_key_path = os.path.join(app.config['USER_PUBLIC_KEYS'], f"{record[0]}.pem")
    with open(public_key_path, "r") as f:
        file_bytes = f.read()
        sk.verifying_key = VerifyingKey.from_pem(file_bytes)
    return sk


def save_uploaded_files(uploaded_file, uploaded_signed_file):
    uploaded_filename = secure_filename(uploaded_file.filename)
    verifiable_uploaded_file_path = os.path.join(app.config['VERIFIABLE_FILES'], uploaded_filename)
    uploaded_file.save(verifiable_uploaded_file_path)
    uploaded_signed_filename = secure_filename(uploaded_signed_file.filename)
    uploaded_signed_file_path = os.path.join(app.config['VERIFIABLE_SIGNED_FILES'], uploaded_signed_filename)
    uploaded_signed_file.save(uploaded_signed_file_path)
    return verifiable_uploaded_file_path, uploaded_signed_file_path


@app.route('/verify_file_chunk', methods=['POST'])
def verify_file_chunk():
    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400

    # Get the uploaded file from the request
    uploaded_file = request.files['file']

    # Check if a file was selected for uploading
    if uploaded_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400

    if 'file' not in request.files:
        return {'message': 'No file part in the request'}, 400

        # Get the uploaded file from the request
    uploaded_signed_file = request.files['signed_file']

    # Check if a file was selected for uploading
    if uploaded_signed_file.filename == '':
        return {'message': 'No file selected for uploading'}, 400
    records = get_user_into(request.form['username'])
    if len(records) == 1:
        record = records[0]
        records2 = get_user_data_storage_info()
        record2 = records2[0]
        # Generate signing and verifying keys
        verifiable_uploaded_file_path, uploaded_signed_file_path = save_uploaded_files(
            uploaded_file=uploaded_file,
            uploaded_signed_file=uploaded_signed_file
        )

        if os.path.exists(os.path.join(app.config['USER_PRIVATE_KEYS'], f"{record[0]}.pem")) and \
                os.path.exists(os.path.join(app.config['USER_PUBLIC_KEYS'], f"{record[0]}.pem")):
            sk = get_signing_key(record=record)
        else:
            return {'message': 'UNABLE TO GET SIGNATURE.'}, 400
        with open(verifiable_uploaded_file_path, "rb") as f:
            readable = f.read()

        with open(uploaded_signed_file_path, "rb") as f:
            data = f.read()
            # print(sk.verifying_key.verify(signature=data, data=readable))
        retrieved_bytes = data_storage.retrieve_bytes(w3, record, data, contract_address=record2[1])
        result = sk.verifying_key.verify(signature=retrieved_bytes, data=readable)

        result2 = sk.verifying_key.verify(signature=data, data=readable)
        print(result2)
        print(result)
    return str(result)


app.run(debug=True, port=5001)
